"""Display logic"""
from openpgp.common import Context


def display(context: Context) -> str:
    r = ['Keys:\n' + '-'*30]
    # workaround because keys are mutable
    parent_keys = []
    subkey_lists = []
    _seen_keys = set()
    for key in sorted(context.keys.values(), key=lambda k: k.parent is not None):
        if key.fingerprint in _seen_keys:
            continue
        _seen_keys.add(key.fingerprint)
        if key.parent is None:
            parent_keys.append(key)
            subkey_lists.append([])
            assert key in parent_keys
        else:
            subkey_lists[parent_keys.index(key.parent)].append(key)
    for parent_key, subkey_list in zip(parent_keys, subkey_lists):
        r.append(str(parent_key))
        for subkey in subkey_list:
            r.append('\t' + str(subkey).replace('\n', '\n\t'))
    r.append('')
    if context.messages:
        r.append('Messages:\n' + '-'*30)
        r.extend(map(str, context.messages))
    return '\n'.join(r)
