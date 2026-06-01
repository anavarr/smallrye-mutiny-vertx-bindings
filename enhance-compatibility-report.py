#!/usr/bin/env python3
"""Post-processes the asciidoctor-generated compatibility report HTML to add interactive filters."""
import glob
import os
import re
import struct
import sys
import xml.etree.ElementTree as ET
import zipfile

INPUT = 'target/compatibility-report.html'
POM = 'pom.xml'
MAVEN_REPO = os.path.expanduser('~/.m2/repository')

Q = r"(?:'|&#8217;|')"

TYPE_CHANGE_PATTERNS = [
    r"original type was '([^']+)" + Q + r"\s*while the new type is '([^']+)" + Q,
    r"return type changed from '([^']+)" + Q + r" to\s+'([^']+)" + Q,
    r"type of the parameter changed from '([^']+)" + Q + r" to '([^']+)" + Q,
    r"type parameters changed from '([^']+)" + Q + r" to '([^']+)" + Q,
]


# --- Type specialization detection ---

def is_type_specialization(html_row):
    if 'A new formal type parameter added' in html_row:
        return True
    for pattern in TYPE_CHANGE_PATTERNS:
        m = re.search(pattern, html_row)
        if m:
            old_type = m.group(1)
            new_type = m.group(2)
            new_base = re.sub(r'&lt;.*', '', new_type)
            if old_type == new_base and old_type != new_type:
                return True
    return False


# --- Vert.x JAR introspection ---

def get_vertx_version():
    try:
        ns = {'m': 'http://maven.apache.org/POM/4.0.0'}
        tree = ET.parse(POM)
        root = tree.getroot()
        for prop in root.findall('.//m:properties/m:vertx.version', ns):
            return prop.text
        for prop in root.findall('.//properties/vertx.version'):
            return prop.text
    except Exception:
        pass
    return None


def build_jar_class_index(vertx_version):
    """Build a mapping from class FQN to JAR path for all Vert.x JARs of the given version."""
    index = {}
    pattern = os.path.join(MAVEN_REPO, 'io', 'vertx', '**', vertx_version, f'*-{vertx_version}.jar')
    jars = [j for j in glob.glob(pattern, recursive=True) if not j.endswith('-sources.jar') and not j.endswith('-javadoc.jar')]
    for jar_path in jars:
        try:
            with zipfile.ZipFile(jar_path, 'r') as zf:
                for name in zf.namelist():
                    if name.endswith('.class') and not name.startswith('META-INF'):
                        fqn = name[:-6].replace('/', '.')
                        index[fqn] = jar_path
        except Exception:
            continue
    return index


def read_class_bytes(class_fqn, jar_path):
    try:
        with zipfile.ZipFile(jar_path, 'r') as zf:
            return zf.read(class_fqn.replace('.', '/') + '.class')
    except Exception:
        return None


def has_vertx_gen(class_fqn, jar_path):
    """Check if a class has @VertxGen by inspecting the bytecode."""
    data = read_class_bytes(class_fqn, jar_path)
    if data is None:
        return None
    return b'io/vertx/codegen/annotations/VertxGen' in data


PRIM_MAP = {'B': 'byte', 'C': 'char', 'D': 'double', 'F': 'float',
            'I': 'int', 'J': 'long', 'S': 'short', 'Z': 'boolean'}


def parse_descriptor_params(descriptor):
    """Parse JVM method descriptor, return tuple of parameter type FQNs."""
    if not descriptor or descriptor[0] != '(':
        return ()
    params = []
    i = 1
    while i < len(descriptor) and descriptor[i] != ')':
        array_depth = 0
        while i < len(descriptor) and descriptor[i] == '[':
            array_depth += 1
            i += 1
        if descriptor[i] == 'L':
            end = descriptor.index(';', i)
            fqn = descriptor[i + 1:end].replace('/', '.')
            params.append(fqn + '[]' * array_depth)
            i = end + 1
        elif descriptor[i] in PRIM_MAP:
            params.append(PRIM_MAP[descriptor[i]] + '[]' * array_depth)
            i += 1
        else:
            break
    return tuple(params)


class ClassInfo:
    """Parsed class file: access flags, method signatures, and field names."""
    ACC_INTERFACE = 0x0200
    ACC_ABSTRACT = 0x0400

    def __init__(self, class_access_flags, methods, fields):
        self.class_access_flags = class_access_flags
        self.methods = methods  # {name: [(params, is_abstract), ...]}
        self.fields = fields    # set of field names

    @property
    def is_interface(self):
        return bool(self.class_access_flags & self.ACC_INTERFACE)

    @property
    def is_abstract(self):
        return bool(self.class_access_flags & self.ACC_ABSTRACT)

    @property
    def is_concrete(self):
        return not self.is_interface and not self.is_abstract


def parse_class(class_data):
    """Parse a .class file and return a ClassInfo."""
    try:
        pos = 8
        cp_count = struct.unpack_from('>H', class_data, pos)[0]
        pos += 2

        utf8 = {}
        i = 1
        while i < cp_count:
            tag = class_data[pos]
            pos += 1
            if tag == 1:
                length = struct.unpack_from('>H', class_data, pos)[0]
                pos += 2
                utf8[i] = class_data[pos:pos + length].decode('utf-8', errors='replace')
                pos += length
            elif tag in (7, 8, 16, 19, 20):
                pos += 2
            elif tag in (3, 4, 9, 10, 11, 12, 17, 18):
                pos += 4
            elif tag in (5, 6):
                pos += 8
                i += 1
            elif tag == 15:
                pos += 3
            else:
                return None
            i += 1

        class_access_flags = struct.unpack_from('>H', class_data, pos)[0]
        pos += 6  # access_flags, this_class, super_class
        iface_count = struct.unpack_from('>H', class_data, pos)[0]
        pos += 2 + iface_count * 2

        # parse fields
        field_count = struct.unpack_from('>H', class_data, pos)[0]
        pos += 2
        fields = set()
        for _ in range(field_count):
            name_idx = struct.unpack_from('>H', class_data, pos + 2)[0]
            pos += 6
            attr_count = struct.unpack_from('>H', class_data, pos)[0]
            pos += 2
            for _ in range(attr_count):
                pos += 2
                attr_len = struct.unpack_from('>I', class_data, pos)[0]
                pos += 4 + attr_len
            if name_idx in utf8:
                fields.add(utf8[name_idx])

        # parse methods
        method_count = struct.unpack_from('>H', class_data, pos)[0]
        pos += 2
        methods = {}
        for _ in range(method_count):
            access_flags = struct.unpack_from('>H', class_data, pos)[0]
            name_idx = struct.unpack_from('>H', class_data, pos + 2)[0]
            desc_idx = struct.unpack_from('>H', class_data, pos + 4)[0]
            pos += 6
            attr_count = struct.unpack_from('>H', class_data, pos)[0]
            pos += 2
            for _ in range(attr_count):
                pos += 2
                attr_len = struct.unpack_from('>I', class_data, pos)[0]
                pos += 4 + attr_len
            name = utf8.get(name_idx, '')
            desc = utf8.get(desc_idx, '')
            params = parse_descriptor_params(desc)
            is_abstract = bool(access_flags & 0x0400)
            methods.setdefault(name, []).append((params, is_abstract))

        return ClassInfo(class_access_flags, methods, fields)
    except Exception:
        return None


def extract_element_params(element):
    """Extract normalized parameter types from an element signature string."""
    paren_start = element.rfind('(')
    paren_end = element.rfind(')')
    if paren_start < 0 or paren_end < 0:
        return None
    param_str = element[paren_start + 1:paren_end]
    param_str = param_str.replace('===', '')
    if not param_str.strip():
        return ()
    while '<' in param_str:
        param_str = re.sub(r'<[^<>]*>', '', param_str)
    params = []
    for p in param_str.split(','):
        p = p.strip()
        if not p:
            continue
        p = p.replace('io.vertx.mutiny.', 'io.vertx.')
        params.append(p)
    return tuple(params)


# --- Mutiny unwrap detection ---

def extract_mutiny_fqns(type_str):
    """Extract all io.vertx.X FQNs from io.vertx.mutiny.X references in a type string."""
    return {'io.vertx.' + m for m in re.findall(r'io\.vertx\.mutiny\.([\w.]+)', type_str)}


def selective_unwrap(type_str, non_vertxgen_types):
    """Replace only non-VertxGen mutiny types with their bare vertx counterparts."""
    result = type_str
    for fqn in sorted(non_vertxgen_types, key=len, reverse=True):
        mutiny_fqn = fqn.replace('io.vertx.', 'io.vertx.mutiny.', 1)
        result = result.replace(mutiny_fqn, fqn)
    return result


def extract_mutiny_unwrap_types(html):
    """Find all unique io.vertx.X types that appear in mutiny→bare-vertx changes."""
    types = set()
    for pattern in TYPE_CHANGE_PATTERNS:
        for m in re.finditer(pattern, html):
            old_type = m.group(1)
            if 'io.vertx.mutiny.' in old_type:
                types.update(extract_mutiny_fqns(old_type))
    return types


def build_non_vertxgen_set(types, jar_index):
    """Return the subset of types that do NOT have @VertxGen in the new version."""
    non_vertxgen = set()
    for fqn in types:
        jar_path = jar_index.get(fqn)
        if jar_path is None:
            continue
        has_gen = has_vertx_gen(fqn, jar_path)
        if has_gen is False:
            non_vertxgen.add(fqn)
    return non_vertxgen


def is_mutiny_unwrap(html_row, non_vertxgen_types, jar_index, vertxgen_cache):
    for pattern in TYPE_CHANGE_PATTERNS:
        m = re.search(pattern, html_row)
        if m:
            old_type = m.group(1)
            new_type = m.group(2)
            transformed = selective_unwrap(old_type, non_vertxgen_types)
            if transformed == new_type and transformed != old_type:
                return True
            # Fallback: if old type references a mutiny class whose bare
            # counterpart is gone or lost @VertxGen, the change is upstream-driven
            # even if the new type is something completely different (renamed class)
            mutiny_fqns = extract_mutiny_fqns(old_type)
            if mutiny_fqns:
                all_gone = all(
                    class_is_still_vertxgen(fqn, jar_index, vertxgen_cache) is not True
                    for fqn in mutiny_fqns
                )
                if all_gone:
                    return True
    return False


# --- Upstream removal detection ---

def class_is_still_vertxgen(bare_class, jar_index, vertxgen_cache):
    """Check if a bare Vert.x class still has @VertxGen. Cached."""
    if bare_class not in vertxgen_cache:
        jar_path = jar_index.get(bare_class)
        if jar_path is None:
            vertxgen_cache[bare_class] = None
        else:
            vertxgen_cache[bare_class] = has_vertx_gen(bare_class, jar_path)
    return vertxgen_cache[bare_class]


def get_class_info(bare_class, jar_index, method_cache):
    """Get parsed ClassInfo for a bare Vert.x class. Cached."""
    if bare_class not in method_cache:
        data = read_class_bytes(bare_class, jar_index[bare_class]) if bare_class in jar_index else None
        method_cache[bare_class] = parse_class(data) if data else None
    return method_cache[bare_class]


def extract_element_class(html_row):
    """Extract the mutiny class FQN from the element (first <code>) of a row."""
    code_m = re.search(r'<code>(.*?)</code>', html_row)
    if not code_m:
        return None
    element = code_m.group(1).replace('&lt;', '<').replace('&gt;', '>').replace('&amp;', '&')
    # Try class::method pattern first
    m = re.search(r'(io\.vertx\.mutiny\.[\w.]+)(?:<[^>]*>)?::', element)
    if m:
        return m.group(1).replace('io.vertx.mutiny.', 'io.vertx.', 1), element
    # Try "class io.vertx.mutiny.X"
    m = re.search(r'class\s+(io\.vertx\.mutiny\.[\w.]+)', element)
    if m:
        return m.group(1).replace('io.vertx.mutiny.', 'io.vertx.', 1), element
    # Try "field io.vertx.mutiny.X.FIELD_NAME" — class is everything up to the last dot
    m = re.search(r'field\s+(io\.vertx\.mutiny\.[\w.]+)\.(\w+)$', element)
    if m:
        return m.group(1).replace('io.vertx.mutiny.', 'io.vertx.', 1), element
    return None


def is_upstream_change(html_row, jar_index, method_cache, vertxgen_cache):
    """Check if a change is due to an upstream Vert.x API change.

    Handles: Class/Method was removed, Class kind changed, Class is now abstract,
    Method now abstract, interface default removed, Class no longer inherits/implements.
    """
    # Extract description
    desc_m = re.findall(r'<p class="tableblock">(.*?)</p>', html_row, re.DOTALL)
    if not desc_m:
        return False
    desc = re.sub(r'<[^>]+>', '', desc_m[-1]).strip()

    result = extract_element_class(html_row)
    if result is None:
        return False
    bare_class, element = result

    # --- Class was removed ---
    if desc == 'Class was removed.':
        vg = class_is_still_vertxgen(bare_class, jar_index, vertxgen_cache)
        return vg is not True

    # --- Method was removed ---
    if desc == 'Method was removed.':
        vg = class_is_still_vertxgen(bare_class, jar_index, vertxgen_cache)
        if vg is None:
            return True
        if vg is False:
            return True

        method_m = re.search(r'(?:<[^>]*>)?::((?:<\w+>|\w+))', element)
        if not method_m:
            return False
        method_name = method_m.group(1)

        class_info = get_class_info(bare_class, jar_index, method_cache)
        if class_info is None:
            return False

        if method_name == '<init>' and not class_info.is_concrete:
            return True

        base_method = method_name
        if not base_method.startswith('<'):
            for suffix in ['AndAwait', 'AndForget']:
                if base_method.endswith(suffix):
                    base_method = base_method[:-len(suffix)]
                    break

        if base_method not in class_info.methods:
            return True

        element_params = extract_element_params(element)
        if element_params is None:
            return False

        is_generated_variant = method_name != base_method

        for overload_params, is_abstract in class_info.methods[base_method]:
            if element_params == overload_params:
                if is_generated_variant and is_abstract:
                    return True
                return False

        return True

    # --- Class kind changed / Class is now abstract ---
    if desc in ("Class kind changed from 'class' to 'interface'.",
                'Class is now abstract.'):
        class_info = get_class_info(bare_class, jar_index, method_cache)
        if class_info is None:
            return False
        if desc == "Class kind changed from 'class' to 'interface'.":
            return class_info.is_interface
        return class_info.is_abstract or class_info.is_interface

    # --- Method now abstract / interface default removed ---
    if desc in ('Method now abstract',
                'The interface no longer has the default implementation of the method.'):
        class_info = get_class_info(bare_class, jar_index, method_cache)
        if class_info is None:
            return False
        if not class_info.is_concrete:
            return True
        method_m = re.search(r'(?:<[^>]*>)?::((?:<\w+>|\w+))', element)
        if not method_m:
            return False
        method_name = method_m.group(1)
        if method_name in class_info.methods:
            for _, is_abstract in class_info.methods[method_name]:
                if is_abstract:
                    return True
        return False

    # --- Method was added to an interface ---
    if desc == 'Method was added to an interface.':
        class_info = get_class_info(bare_class, jar_index, method_cache)
        if class_info is None:
            return False
        return class_info.is_interface

    # --- Class no longer inherits/implements ---
    if desc.startswith('Class no longer inherits from') or desc.startswith('Class no longer implements interface'):
        class_info = get_class_info(bare_class, jar_index, method_cache)
        return class_info is not None

    # --- Field removed ---
    if desc in ('Field was removed from the class.',
                'Field with constant value has been removed.'):
        vg = class_is_still_vertxgen(bare_class, jar_index, vertxgen_cache)
        if vg is None:
            return True
        if vg is False:
            return True
        class_info = get_class_info(bare_class, jar_index, method_cache)
        if class_info is None:
            return False
        field_m = re.search(r'(io\.vertx\.mutiny\.[\w.]+)\.(\w+)$', element)
        if not field_m:
            return False
        field_name = field_m.group(2)
        return field_name not in class_info.fields

    # --- Number of parameters changed ---
    if desc == 'The number of parameters of the method have changed.':
        vg = class_is_still_vertxgen(bare_class, jar_index, vertxgen_cache)
        if vg is None:
            return True
        if vg is False:
            return True
        class_info = get_class_info(bare_class, jar_index, method_cache)
        if class_info is None:
            return False
        method_m = re.search(r'(?:<[^>]*>)?::((?:<\w+>|\w+))', element)
        if not method_m:
            return False
        method_name = method_m.group(1)
        base_method = method_name
        if not base_method.startswith('<'):
            for suffix in ['AndAwait', 'AndForget', 'Blocking']:
                if base_method.endswith(suffix):
                    base_method = base_method[:-len(suffix)]
                    break
        if base_method not in class_info.methods:
            return True
        element_params = extract_element_params(element)
        if element_params is None:
            return False
        for overload_params, _ in class_info.methods[base_method]:
            if element_params == overload_params:
                return False
        return True

    # --- Type changed with no mutiny types involved (pure upstream API change) ---
    for pattern in TYPE_CHANGE_PATTERNS:
        m = re.search(pattern, html_row)
        if m:
            old_type = m.group(1)
            new_type = m.group(2)
            if 'io.vertx.mutiny.' not in old_type and 'io.vertx.mutiny.' not in new_type:
                return True
            break

    return False


# --- Categorization ---

def categorize_row(html_row, non_vertxgen_types, jar_index, method_cache, vertxgen_cache):
    if is_type_specialization(html_row):
        return 'type-specialization'
    if non_vertxgen_types and is_mutiny_unwrap(html_row, non_vertxgen_types, jar_index, vertxgen_cache):
        return 'mutiny-unwrap'
    if jar_index and is_upstream_change(html_row, jar_index, method_cache, vertxgen_cache):
        return 'upstream-removal'
    desc_m = re.findall(r'<p class="tableblock">(.*?)</p>', html_row, re.DOTALL)
    if desc_m:
        desc_text = re.sub(r'<[^>]+>', '', desc_m[-1]).strip()
        if desc_text == 'Method was added to an interface.':
            code_m = re.search(r'<code>(.*?)</code>', html_row)
            if code_m and code_m.group(1) == 'null':
                return 'revapi-noise'
    return 'codegen'


# --- HTML injection ---

FILTER_PANEL = """\
<div id="compat-filters" style="position:sticky;top:0;z-index:100;background:#f4f6f9;border:1px solid #d0d7de;border-radius:0 0 6px 6px;padding:14px 20px;margin-bottom:20px;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;font-size:14px;box-shadow:0 2px 8px rgba(0,0,0,0.1)">
<div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:8px">
<strong>Filters</strong>
<span style="font-size:12px"><a href="#" id="select-all" style="color:#0969da;text-decoration:none">show all</a> · <a href="#" id="select-none" style="color:#0969da;text-decoration:none">hide all</a></span>
</div>
<label style="display:flex;align-items:center;gap:8px;cursor:pointer;padding:4px 0">
<input type="checkbox" id="filter-type-specialization" style="width:15px;height:15px">
<span>Show type specialization changes</span>
<span id="count-type-specialization" style="background:#ddf4ff;color:#0969da;border-radius:10px;padding:1px 8px;font-size:12px;font-weight:600">0</span>
<span style="color:#666;font-size:12px;margin-left:4px">(e.g. MyType &rarr; MyType&lt;T&gt;)</span>
</label>
<label style="display:flex;align-items:center;gap:8px;cursor:pointer;padding:4px 0">
<input type="checkbox" id="filter-mutiny-unwrap" style="width:15px;height:15px">
<span>Show mutiny wrapper removal</span>
<span id="count-mutiny-unwrap" style="background:#ddf4ff;color:#0969da;border-radius:10px;padding:1px 8px;font-size:12px;font-weight:600">0</span>
<span style="color:#666;font-size:12px;margin-left:4px">(io.vertx.mutiny.X &rarr; io.vertx.X, verified no @VertxGen in new version)</span>
</label>
<label style="display:flex;align-items:center;gap:8px;cursor:pointer;padding:4px 0">
<input type="checkbox" id="filter-upstream-removal" style="width:15px;height:15px">
<span>Show upstream Vert.x API changes</span>
<span id="count-upstream-removal" style="background:#ddf4ff;color:#0969da;border-radius:10px;padding:1px 8px;font-size:12px;font-weight:600">0</span>
<span style="color:#666;font-size:12px;margin-left:4px">(removals, class&rarr;interface, now abstract &mdash; verified against upstream bytecode)</span>
</label>
<label style="display:flex;align-items:center;gap:8px;cursor:pointer;padding:4px 0">
<input type="checkbox" id="filter-codegen" checked style="width:15px;height:15px">
<span>Show potentially code-gen related</span>
<span id="count-codegen" style="background:#fff3cd;color:#856404;border-radius:10px;padding:1px 8px;font-size:12px;font-weight:600">0</span>
<span style="color:#666;font-size:12px;margin-left:4px">(changes not explained by upstream &mdash; may need investigation)</span>
</label>
<label style="display:flex;align-items:center;gap:8px;cursor:pointer;padding:4px 0">
<input type="checkbox" id="filter-revapi-noise" style="width:15px;height:15px">
<span>Show revapi artifacts</span>
<span id="count-revapi-noise" style="background:#e2e3e5;color:#495057;border-radius:10px;padding:1px 8px;font-size:12px;font-weight:600">0</span>
<span style="color:#666;font-size:12px;margin-left:4px">(null elements, unresolvable entries)</span>
</label>
</div>
"""

SCRIPT = """\
<script>
(function() {
  var categories = ['type-specialization', 'mutiny-unwrap', 'upstream-removal', 'codegen', 'revapi-noise'];

  categories.forEach(function(cat) {
    var cb = document.getElementById('filter-' + cat);
    var badge = document.getElementById('count-' + cat);
    var rows = document.querySelectorAll('tr[data-category="' + cat + '"]');
    badge.textContent = rows.length;
    if (rows.length === 0) cb.closest('label').style.display = 'none';
  });

  function update() {
    categories.forEach(function(cat) {
      var cb = document.getElementById('filter-' + cat);
      var show = cb.checked;
      document.querySelectorAll('tr[data-category="' + cat + '"]').forEach(function(row) {
        row.style.display = show ? '' : 'none';
      });
    });
    document.querySelectorAll('.sect1').forEach(function(sect) {
      var tbody = sect.querySelector('tbody');
      if (!tbody) return;
      var allRows = tbody.querySelectorAll('tr');
      var visible = 0;
      allRows.forEach(function(r) { if (r.style.display !== 'none') visible++; });
      var h2 = sect.querySelector('h2');
      if (!h2) return;
      var counter = h2.querySelector('.row-counter');
      if (!counter) {
        counter = document.createElement('span');
        counter.className = 'row-counter';
        counter.style.cssText = 'font-size:13px;color:#666;font-weight:400;margin-left:8px';
        h2.appendChild(counter);
      }
      counter.textContent = '(' + visible + ' / ' + allRows.length + ')';
    });
  }

  categories.forEach(function(cat) {
    document.getElementById('filter-' + cat).addEventListener('change', update);
  });

  function setAll(checked) {
    categories.forEach(function(cat) {
      document.getElementById('filter-' + cat).checked = checked;
    });
    update();
  }
  document.getElementById('select-all').addEventListener('click', function(e) { e.preventDefault(); setAll(true); });
  document.getElementById('select-none').addEventListener('click', function(e) { e.preventDefault(); setAll(false); });

  update();
})();
</script>
"""


def process(html, non_vertxgen_types, jar_index):
    method_cache = {}
    vertxgen_cache = {}
    counts = {'type-specialization': 0, 'mutiny-unwrap': 0, 'upstream-removal': 0, 'codegen': 0, 'revapi-noise': 0}

    HIDDEN_BY_DEFAULT = {'type-specialization', 'mutiny-unwrap', 'upstream-removal', 'revapi-noise'}

    def tag_row(match):
        row = match.group(0)
        cat = categorize_row(row, non_vertxgen_types, jar_index, method_cache, vertxgen_cache)
        counts[cat] += 1
        hidden = ' style="display:none"' if cat in HIDDEN_BY_DEFAULT else ''
        return row.replace('<tr>', '<tr data-category="' + cat + '"' + hidden + '>', 1)

    def process_tbody(match):
        tbody_content = match.group(0)
        return re.sub(r'<tr>\n(.*?)</tr>', tag_row, tbody_content, flags=re.DOTALL)

    html = re.sub(r'<tbody>.*?</tbody>', process_tbody, html, flags=re.DOTALL)

    html = html.replace('<div id="content">', '<div id="content">\n' + FILTER_PANEL, 1)

    html = html.replace('</body>', SCRIPT + '</body>', 1)

    return html, counts


def main():
    input_path = sys.argv[1] if len(sys.argv) > 1 else INPUT

    with open(input_path, 'r') as f:
        html = f.read()

    non_vertxgen_types = set()
    jar_index = {}
    vertx_version = get_vertx_version()
    if vertx_version:
        print(f'Vert.x version: {vertx_version}')
        jar_index = build_jar_class_index(vertx_version)
        print(f'Indexed {len(jar_index)} classes from {len(set(jar_index.values()))} JARs')
        candidate_types = extract_mutiny_unwrap_types(html)
        non_vertxgen_types = build_non_vertxgen_set(candidate_types, jar_index)
        verified = candidate_types - non_vertxgen_types
        not_found = candidate_types - non_vertxgen_types - {t for t in candidate_types if t in jar_index}
        if non_vertxgen_types:
            print(f'Confirmed no @VertxGen: {", ".join(sorted(non_vertxgen_types))}')
        if verified & set(jar_index):
            still_vertxgen = verified & set(jar_index)
            if still_vertxgen:
                print(f'Still @VertxGen (kept as real changes): {", ".join(sorted(still_vertxgen))}')
        if not_found:
            print(f'Not found in JARs (skipped): {", ".join(sorted(not_found))}')
    else:
        print('Warning: could not detect vertx.version from pom.xml, skipping bytecode checks')

    html, counts = process(html, non_vertxgen_types, jar_index)

    with open(input_path, 'w') as f:
        f.write(html)

    hidden = sum(v for k, v in counts.items() if k != 'codegen')
    print(f'Enhanced report: {hidden} rows hidden by default ({counts["type-specialization"]} type-spec, {counts["mutiny-unwrap"]} mutiny-unwrap, {counts["upstream-removal"]} upstream, {counts["revapi-noise"]} revapi-noise), {counts["codegen"]} potentially code-gen related')


if __name__ == '__main__':
    main()
