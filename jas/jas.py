def get_index(line, idx):
    if idx.startswith('0x') or idx.endswith('h'):
        val = int(idx, 16)
    elif idx.startswith('0'):
        val = int(idx, 8)
    else:
        val = int(idx)

    return val

def get_second_token(line):
    tokens = line.split(' ')
    if len(tokens) != 2:
        print('Error parsing {}:'.format(tokens[0]))
        print('  {}'.format(line))
        sys.exit(1)

    return tokens[1]

def _aload(line):
    # expects: aload idx
    idx = get_second_token(line)
    idx = get_index(line, idx)

    if idx < 0 or idx > 255:
        print('Error parsing aload (index):')
        print('  {}'.format(line))
        sys.exit(1)
    
    return idx

def _anewarray(line):
    # expects: anewarray class
    class_name = get_second_token(line)

    # iterate constant pool
    # find class reference named class_name
    # split index into two bytes
    pass

def _astore(line):
    # expects: astore idx
    idx = get_second_token(line)
    idx = get_index(line, idx)

    if idx < 0 or idx > 255:
        print('Error parsing astore (index):')
        print('  {}'.format(line))
        sys.exit(1)
    
    return idx

def _bipush(line):
    # expects: bipush value8_t
    idx = get_second_token(line)
    idx = get_index(line, idx)

    if idx < 0 or idx > 255:
        print('Error parsing bipush (index):')
        print('  {}'.format(line))
        sys.exit(1)
    
    return idx

def _checkcast(line):
    class_name = get_second_token(line)

    # iterate constant pool
    # find class reference named class_name
    # split index into two bytes
    pass

def _dload(line):
    # expects: dload idx
    idx = get_second_token(line)
    idx = get_index(line, idx)

    if idx < 0 or idx > 255:
        print('Error parsing dload (index):')
        print('  {}'.format(line))
        sys.exit(1)
    
    return idx

def _dstore(line):
    idx = get_second_token(line)
    idx = get_index(line, idx)

    if idx < 0 or idx > 255:
        print('Error parsing dstore (index):')
        print('  {}'.format(line))
        sys.exit(1)
    
    return idx

def _fload(line):
    idx = get_second_token(line)
    idx = get_index(line, idx)

    if idx < 0 or idx > 255:
        print('Error parsing fload (index):')
        print('  {}'.format(line))
        sys.exit(1)
    
    return idx

def _fstore(line):
    idx = get_second_token(line)
    idx = get_index(line, idx)

    if idx < 0 or idx > 255:
        print('Error parsing fstore (index):')
        print('  {}'.format(line))
        sys.exit(1)
    
    return idx

def _getfield(line):
    # expects: getfield field_name
    field_name = get_second_token(line)

    # iterate constant pool
    # find field reference named field_name
    # split index into two bytes
    pass

def _getstatic(line):
    # expects: getstatic field_name
    field_name = get_second_token(line)

    # iterate constant pool
    # find field reference named field_name
    # split index into two bytes
    pass

def _goto(line):
    # expects: goto label
    label = get_second_token(line)
    return {'type': 'label', 'label': label, 'size': 2}

def _goto_w(line):
    label = get_second_token(line)
    return {'type': 'label', 'label': label, 'size': 4}

def _if_acmpeq(line):
    label = get_second_token(line)
    return {'type': 'label', 'label': label, 'size': 2}

def _if_acmpne(line):
    label = get_second_token(line)
    return {'type': 'label', 'label': label, 'size': 2}

def _if_icmpeq(line):
    label = get_second_token(line)
    return {'type': 'label', 'label': label, 'size': 2}

def _if_icmpge(line):
    label = get_second_token(line)
    return {'type': 'label', 'label': label, 'size': 2}

def _if_icmpgt(line):
    label = get_second_token(line)
    return {'type': 'label', 'label': label, 'size': 2}

def _if_icmple(line):
    label = get_second_token(line)
    return {'type': 'label', 'label': label, 'size': 2}

def _if_icmplt(line):
    label = get_second_token(line)
    return {'type': 'label', 'label': label, 'size': 2}

def _if_icmpne(line):
    label = get_second_token(line)
    return {'type': 'label', 'label': label, 'size': 2}

def _ifeq(line):
    label = get_second_token(line)
    return {'type': 'label', 'label': label, 'size': 2}

def _ifge(line):
    label = get_second_token(line)
    return {'type': 'label', 'label': label, 'size': 2}

def _ifgt(line):
    label = get_second_token(line)
    return {'type': 'label', 'label': label, 'size': 2}

def _ifle(line):
    label = get_second_token(line)
    return {'type': 'label', 'label': label, 'size': 2}

def _iflt(line):
    label = get_second_token(line)
    return {'type': 'label', 'label': label, 'size': 2}

def _ifne(line):
    label = get_second_token(line)
    return {'type': 'label', 'label': label, 'size': 2}

def _ifnonnull(line):
    label = get_second_token(line)
    return {'type': 'label', 'label': label, 'size': 2}

def _ifnull(line):
    label = get_second_token(line)
    return {'type': 'label', 'label': label, 'size': 2}

def _iinc(line):
    # expects: iinc idx val
    tokens = line.split(' ')
    if len(tokens) != 3:
        print('Error parsing {}:'.format(tokens[0]))
        print('  {}'.format(line))
        sys.exit(1)

    idx = get_index(line, tokens[1])
    val = get_index(line, tokens[2])
    return [idx, val]

def _iload(line):
    idx = get_second_token(line)
    idx = get_index(line, idx)

    if idx < 0 or idx > 255:
        print('Error parsing iload (index):')
        print('  {}'.format(line))
        sys.exit(1)
    
    return idx

def _instanceof(line):
    # expects: instanceof class_name
    class_name = get_second_token(line)

    # iterate constant pool
    # find class reference named class_name
    # split index into two bytes
    pass

def _invokedynamic(line):
    # expects: invokedynamic method_name
    method_name = get_second_token(line)

    # iterate constant pool
    # find method reference named method_name
    # split index into two bytes
    b1 = 0 << 8
    b2 = 0
    return [b1, b2, 0, 0]

# TODO: count
def _invokeinterface(line):
    # expects: invokedynamic method_name
    method_name = get_second_token(line)

    # iterate constant pool
    # find method reference named method_name
    # split index into two bytes
    b1 = 0 << 8
    b2 = 0
    count = 0 # num args
    return [b1, b2, count, 0]

def _invokespecial(line):
    # expects: invokespecial method_name
    method_name = get_second_token(line)

    # iterate constant pool
    # find method reference named method_name
    # split index into two bytes
    b1 = 0 << 8
    b2 = 0
    return [b1, b2]

def _invokestatic(line):
    # expects: invokestatic method_name
    method_name = get_second_token(line)

    # iterate constant pool
    # find method reference named method_name
    # split index into two bytes
    b1 = 0 << 8
    b2 = 0
    return [b1, b2]

def _invokevirtual(line):
    # expects: invokevirtual method_name
    method_name = get_second_token(line)

    # iterate constant pool
    # find method reference named method_name
    # split index into two bytes
    b1 = 0 << 8
    b2 = 0
    return [b1, b2]

def _istore(line):
    idx = get_second_token(line)
    idx = get_index(line, idx)

    if idx < 0 or idx > 255:
        print('Error parsing iload (index):')
        print('  {}'.format(line))
        sys.exit(1)
    
    return idx

def _jsr(line):
    label = get_second_token(line)
    return {'type': 'label', 'label': label, 'size': 2}

def _jsr_w(line):
    label = get_second_token(line)
    return {'type': 'label', 'label': label, 'size': 4}

# TODO: handle by variable name?
def _ldc(line):
    idx = get_second_token(line)
    idx = get_index(line, idx)

    if idx < 0 or idx > 255:
        print('Error parsing iload (index):')
        print('  {}'.format(line))
        sys.exit(1)
    
    return idx

def _ldc_w(line):
    tokens = line.split(' ')
    if len(tokens) != 3:
        print('Error parsing {}:'.format(tokens[0]))
        print('  {}'.format(line))
        sys.exit(1)

    idx1 = get_index(line, tokens[1])
    idx2 = get_index(line, tokens[2])
    return [idx1, idx2]

def _ldc2_w(line):
    tokens = line.split(' ')
    if len(tokens) != 3:
        print('Error parsing {}:'.format(tokens[0]))
        print('  {}'.format(line))
        sys.exit(1)

    idx1 = get_index(line, tokens[1])
    idx2 = get_index(line, tokens[2])
    return [idx1, idx2]

def _lload(line):
    idx = get_second_token(line)
    idx = get_index(line, idx)

    if idx < 0 or idx > 255:
        print('Error parsing iload (index):')
        print('  {}'.format(line))
        sys.exit(1)
    
    return idx

def _lookupswitch(line):
    pass

def _lstore(line):
    idx = get_second_token(line)
    idx = get_index(line, idx)

    if idx < 0 or idx > 255:
        print('Error parsing iload (index):')
        print('  {}'.format(line))
        sys.exit(1)
    
    return idx

def _multianewarray(line):
    pass

def _new(line):
    pass

# TODO: maybe use type name?
def _newarray(line):
    idx = get_second_token(line)
    idx = get_index(line, idx)

    if idx < 0 or idx > 255:
        print('Error parsing newarray (type):')
        print('  {}'.format(line))
        sys.exit(1)
    
    return idx

def _putfield(line):
    field_name = get_second_token(line)

    # iterate constant pool
    # find field reference named field_name
    # split index into two bytes
    b1 = 0 << 8
    b2 = 0
    return [b1, b2]

def _putstatic(line):
    field_name = get_second_token(line)

    # iterate constant pool
    # find field reference named field_name
    # split index into two bytes
    b1 = 0 << 8
    b2 = 0
    return [b1, b2]

def _ret(line):
    idx = get_second_token(line)
    idx = get_index(line, idx)

    if idx < 0 or idx > 255:
        print('Error parsing iload (index):')
        print('  {}'.format(line))
        sys.exit(1)
    
    return idx

def _sipush(line):
    idx = get_second_token(line)
    idx = get_index(line, idx)

    if idx < -32768 or idx > 32767:
        print('Error parsing sipush (index):')
        print('  {}'.format(line))
        sys.exit(1)

    idx1 = idx >> 8 & 0xFF
    idx2 = idx & 0xFF
    return [idx1, idx2]

def _tableswitch(line):
    pass

def _wide(line):
    pass


lookup = {
    'aaload': {
        'opcode': 0x32,
        'extra': None
    },
    'aastore': {
        'opcode': 0x53,
        'extra': None
    },
    'aconst_null': {
        'opcode': 0x01,
        'extra': None
    },
    'aload': {
        'opcode': 0x19,
        'extra': _aload
    },
    'aload_0': {
        'opcode': 0x2a,
        'extra': None
    },
    'aload_1': {
        'opcode': 0x2b,
        'extra': None
    },
    'aload_2': {
        'opcode': 0x2c,
        'extra': None
    },
    'aload_3': {
        'opcode': 0x2d,
        'extra': None
    },
    'anewarray': {
        'opcode': 0xbd,
        'extra': 2
    },
    'areturn': {
        'opcode': 0xb0,
        'extra': None,
    },
    'arraylength': {
        'opcode': 0xbe,
        'extra': None,
    },
    'astore': {
        'opcode': 0x3a,
        'extra': 1,
    },
    'astore_0': {
        'opcode': 0x4b,
        'extra': None,
    },
    'astore_1': {
        'opcode': 0x4c,
        'extra': None,
    },
    'astore_2': {
        'opcode': 0x4d,
        'extra': None,
    },
    'astore_3': {
        'opcode': 0x4e,
        'extra': None,
    },
    'athrow': {
        'opcode': 0xbf,
        'extra': None,
    },
    'baload': {
        'opcode': 0x33,
        'extra': None,
    },
    'bastore': {
        'opcode': 0x54,
        'extra': None,
    },
    'bipush': {
        'opcode': 0x10,
        'extra': 1,
    },
    'breakpoint': {
        'opcode': 0xca,
        'extra': None,
    },
    'caload': {
        'opcode': 0x34,
        'extra': None,
    },
    'castore': {
        'opcode': 0x55,
        'extra': None,
    },
    'checkcast': {
        'opcode': 0xc0,
        'extra': 2,
    },
    'd2f': {
        'opcode': 0x90,
        'extra': None,
    },
    'd2i': {
        'opcode': 0x8e,
        'extra': None,
    },
    'd2l': {
        'opcode': 0x8f,
        'extra': None,
    },
    'dadd': {
        'opcode': 0x63,
        'extra': None,
    },
    'daload': {
        'opcode': 0x31,
        'extra': None,
    },
    'dastore': {
        'opcode': 0x52,
        'extra': None,
    },
    'dcmpg': {
        'opcode': 0x98,
        'extra': None,
    },
    'dcmpl': {
        'opcode': 0x97,
        'extra': None,
    },
    'dconst_0': {
        'opcode': 0x0e,
        'extra': None,
    },
    'dconst_1': {
        'opcode': 0x0f,
        'extra': None,
    },
    'ddiv': {
        'opcode': 0x6f,
        'extra': None,
    },
    'dload': {
        'opcode': 0x18,
        'extra': 1,
    },
    'dload_0': {
        'opcode': 0x26,
        'extra': None,
    },
    'dload_1': {
        'opcode': 0x27,
        'extra': None,
    },
    'dload_2': {
        'opcode': 0x28,
        'extra': None,
    },
    'dload_3': {
        'opcode': 0x29,
        'extra': None,
    },
    'dmul': {
        'opcode': 0x6b,
        'extra': None,
    },
    'dneg': {
        'opcode': 0x77,
        'extra': None,
    },
    'drem': {
        'opcode': 0x73,
        'extra': None,
    },
    'dreturn': {
        'opcode': 0xaf,
        'extra': None,
    },
    'dstore': {
        'opcode': 0x39,
        'extra': 1,
    },
    'dstore_0': {
        'opcode': 0x47,
        'extra': None,
    },
    'dstore_1': {
        'opcode': 0x48,
        'extra': None,
    },
    'dstore_2': {
        'opcode': 0x49,
        'extra': None,
    },
    'dstore_3': {
        'opcode': 0x4a,
        'extra': None,
    },
    'dsub': {
        'opcode': 0x67,
        'extra': None,
    },
    'dup': {
        'opcode': 0x59,
        'extra': None,
    },
    'dup_x1': {
        'opcode': 0x5a,
        'extra': None,
    },
    'dup_x2': {
        'opcode': 0x5b,
        'extra': None,
    },
    'dup2': {
        'opcode': 0x5c,
        'extra': None,
    },
    'dup2_x1': {
        'opcode': 0x5d,
        'extra': None,
    },
    'dup2_x2': {
        'opcode': 0x5e,
        'extra': None,
    },
    'f2d': {
        'opcode': 0x8d,
        'extra': None,
    },
    'f2i': {
        'opcode': 0x8b,
        'extra': None,
    },
    'f2l': {
        'opcode': 0x8c,
        'extra': None,
    },
    'fadd': {
        'opcode': 0x62,
        'extra': None,
    },
    'faload': {
        'opcode': 0x30,
        'extra': None,
    },
    'fastore': {
        'opcode': 0x51,
        'extra': None,
    },
    'fcmpg': {
        'opcode': 0x96,
        'extra': None,
    },
    'fcmpl': {
        'opcode': 0x95,
        'extra': None,
    },
    'fconst_0': {
        'opcode': 0x0b,
        'extra': None,
    },
    'fconst_1': {
        'opcode': 0x0c,
        'extra': None,
    },
    'fconst_2': {
        'opcode': 0x0d,
        'extra': None,
    },
    'fdiv': {
        'opcode': 0x6e,
        'extra': None,
    },
    'fload': {
        'opcode': 0x17,
        'extra': 1,
    },
    'fload_0': {
        'opcode': 0x22,
        'extra': None,
    },
    'fload_1': {
        'opcode': 0x23,
        'extra': None,
    },
    'fload_2': {
        'opcode': 0x24,
        'extra': None,
    },
    'fload_3': {
        'opcode': 0x25,
        'extra': None,
    },
    'fmul': {
        'opcode': 0x6a,
        'extra': None,
    },
    'fneg': {
        'opcode': 0x76,
        'extra': None,
    },
    'frem': {
        'opcode': 0x72,
        'extra': None,
    },
    'freturn': {
        'opcode': 0xae,
        'extra': None,
    },
    'fstore': {
        'opcode': 0x38,
        'extra': 1,
    },
    'fstore_0': {
        'opcode': 0x43,
        'extra': None,
    },
    'fstore_1': {
        'opcode': 0x44,
        'extra': None,
    },
    'fstore_2': {
        'opcode': 0x45,
        'extra': None,
    },
    'fstore_3': {
        'opcode': 0x46,
        'extra': None,
    },
    'fsub': {
        'opcode': 0x66,
        'extra': None,
    },
    'getfield': {
        'opcode': 0xb4,
        'extra': 2,
    },
    'getstatic': {
        'opcode': 0xb2,
        'extra': 2,
    },
    'goto': {
        'opcode': 0xa7,
        'extra': 2,
    },
    'goto_w': {
        'opcode': 0xc8,
        'extra': 4,
    },
    'i2b': {
        'opcode': 0x91,
        'extra': None,
    },
    'i2c': {
        'opcode': 0x92,
        'extra': None,
    },
    'i2d': {
        'opcode': 0x87,
        'extra': None,
    },
    'i2f': {
        'opcode': 0x86,
        'extra': None,
    },
    'i2l': {
        'opcode': 0x85,
        'extra': None,
    },
    'i2s': {
        'opcode': 0x93,
        'extra': None,
    },
    'iadd': {
        'opcode': 0x60,
        'extra': None,
    },
    'iaload': {
        'opcode': 0x2e,
        'extra': None,
    },
    'iand': {
        'opcode': 0x7e,
        'extra': None,
    },
    'iastore': {
        'opcode': 0x4f,
        'extra': None,
    },
    'iconst_m1': {
        'opcode': 0x02,
        'extra': None,
    },
    'iconst_0': {
        'opcode': 0x03,
        'extra': None,
    },
    'iconst_1': {
        'opcode': 0x04,
        'extra': None,
    },
    'iconst_2': {
        'opcode': 0x05,
        'extra': None,
    },
    'iconst_3': {
        'opcode': 0x06,
        'extra': None,
    },
    'iconst_4': {
        'opcode': 0x07,
        'extra': None,
    },
    'iconst_5': {
        'opcode': 0x08,
        'extra': None,
    },
    'idiv': {
        'opcode': 0x6c,
        'extra': None,
    },
    'if_acmpeq': {
        'opcode': 0xa5,
        'extra': 2,
    },
    'if_acmpne': {
        'opcode': 0xa6,
        'extra': 2,
    },
    'if_icmpeq': {
        'opcode': 0x9f,
        'extra': 2,
    },
    'if_icmpge': {
        'opcode': 0xa2,
        'extra': 2,
    },
    'if_icmpgt': {
        'opcode': 0xa3,
        'extra': 2,
    },
    'if_icmple': {
        'opcode': 0xa4,
        'extra': 2,
    },
    'if_icmplt': {
        'opcode': 0xa1,
        'extra': 2,
    },
    'if_icmpne': {
        'opcode': 0xa0,
        'extra': 2,
    },
    'ifeq': {
        'opcode': 0x99,
        'extra': 2,
    },
    'ifge': {
        'opcode': 0x9c,
        'extra': 2,
    },
    'ifgt': {
        'opcode': 0x9d,
        'extra': 2,
    },
    'ifle': {
        'opcode': 0x9e,
        'extra': 2,
    },
    'iflt': {
        'opcode': 0x9b,
        'extra': 2,
    },
    'ifne': {
        'opcode': 0x9a,
        'extra': 2,
    },
    'ifnonnull': {
        'opcode': 0xc7,
        'extra': 2,
    },
    'ifnull': {
        'opcode': 0xc6,
        'extra': 2,
    },
    'iinc': {
        'opcode': 0x84,
        'extra': 2,
    },
    'iload': {
        'opcode': 0x15,
        'extra': 1,
    },
    'iload_0': {
        'opcode': 0x1a,
        'extra': None,
    },
    'iload_1': {
        'opcode': 0x1b,
        'extra': None,
    },
    'iload_2': {
        'opcode': 0x1c,
        'extra': None,
    },
    'iload_3': {
        'opcode': 0x1d,
        'extra': None,
    },
    'impdep1': {
        'opcode': 0xfe,
        'extra': None,
    },
    'impdep2': {
        'opcode': 0xff,
        'extra': None,
    },
    'imul': {
        'opcode': 0x68,
        'extra': None,
    },
    'ineg': {
        'opcode': 0x74,
        'extra': None,
    },
    'instanceof': {
        'opcode': 0xc1,
        'extra': 2,
    },
    'invokedynamic': {
        'opcode': 0xba,
        'extra': 4,
    },
    'invokeinterface': {
        'opcode': 0xb9,
        'extra': 4,
    },
    'invokespecial': {
        'opcode': 0xb7,
        'extra': 2,
    },
    'invokestatic': {
        'opcode': 0xb8,
        'extra': 2,
    },
    'invokevirtual': {
        'opcode': 0xb6,
        'extra': 2,
    },
    'ior': {
        'opcode': 0x80,
        'extra': None,
    },
    'irem': {
        'opcode': 0x70,
        'extra': None,
    },
    'ireturn': {
        'opcode': 0xac,
        'extra': None,
    },
    'ishl': {
        'opcode': 0x78,
        'extra': None,
    },
    'ishr': {
        'opcode': 0x7a,
        'extra': None,
    },
    'istore': {
        'opcode': 0x36,
        'extra': 1,
    },
    'istore_0': {
        'opcode': 0x3b,
        'extra': None,
    },
    'istore_1': {
        'opcode': 0x3c,
        'extra': None,
    },
    'istore_2': {
        'opcode': 0x3d,
        'extra': None,
    },
    'istore_3': {
        'opcode': 0x3e,
        'extra': None,
    },
    'isub': {
        'opcode': 0x64,
        'extra': None,
    },
    'iushr': {
        'opcode': 0x7c,
        'extra': None,
    },
    'ixor': {
        'opcode': 0x82,
        'extra': None,
    },
    'jsr': {
        'opcode': 0xa8,
        'extra': 2,
    },
    'jsr_w': {
        'opcode': 0xc9,
        'extra': 4,
    },
    'l2d': {
        'opcode': 0x8a,
        'extra': None,
    },
    'l2f': {
        'opcode': 0x89,
        'extra': None,
    },
    'l2i': {
        'opcode': 0x88,
        'extra': None,
    },
    'ladd': {
        'opcode': 0x61,
        'extra': None,
    },
    'laload': {
        'opcode': 0x2f,
        'extra': None,
    },
    'land': {
        'opcode': 0x7f,
        'extra': None,
    },
    'lastore': {
        'opcode': 0x50,
        'extra': None,
    },
    'lcmp': {
        'opcode': 0x94,
        'extra': None,
    },
    'lconst_0': {
        'opcode': 0x09,
        'extra': None,
    },
    'lconst_1': {
        'opcode': 0x0a,
        'extra': None,
    },
    'ldc': {
        'opcode': 0x12,
        'extra': 1,
    },
    'ldc_w': {
        'opcode': 0x13,
        'extra': 2,
    },
    'ldc2_w': {
        'opcode': 0x14,
        'extra': 2,
    },
    'ldiv': {
        'opcode': 0x6d,
        'extra': None,
    },
    'lload': {
        'opcode': 0x16,
        'extra': 1,
    },
    'lload_0': {
        'opcode': 0x1e,
        'extra': None,
    },
    'lload_1': {
        'opcode': 0x1f,
        'extra': None,
    },
    'lload_2': {
        'opcode': 0x20,
        'extra': None,
    },
    'lload_3': {
        'opcode': 0x21,
        'extra': None,
    },
    'lmul': {
        'opcode': 0x69,
        'extra': None,
    },
    'lneg': {
        'opcode': 0x75,
        'extra': None,
    },
    'lookupswitch': {
        'opcode': 0xab,
        'extra': [8, None],
    },
    'lor': {
        'opcode': 0x81,
        'extra': None,
    },
    'lrem': {
        'opcode': 0x71,
        'extra': None,
    },
    'lreturn': {
        'opcode': 0xad,
        'extra': None,
    },
    'lshl': {
        'opcode': 0x79,
        'extra': None,
    },
    'lshr': {
        'opcode': 0x7b,
        'extra': None,
    },
    'lstore': {
        'opcode': 0x37,
        'extra': 1,
    },
    'lstore_0': {
        'opcode': 0x3f,
        'extra': None,
    },
    'lstore_1': {
        'opcode': 0x40,
        'extra': None,
    },
    'lstore_2': {
        'opcode': 0x41,
        'extra': None,
    },
    'lstore_3': {
        'opcode': 0x42,
        'extra': None,
    },
    'lsub': {
        'opcode': 0x65,
        'extra': None,
    },
    'lushr': {
        'opcode': 0x7d,
        'extra': None,
    },
    'lxor': {
        'opcode': 0x83,
        'extra': None,
    },
    'monitorenter': {
        'opcode': 0xc2,
        'extra': None,
    },
    'monitorexit': {
        'opcode': 0xc3,
        'extra': None,
    },
    'multianewarray': {
        'opcode': 0xc5,
        'extra': 3,
    },
    'new': {
        'opcode': 0xbb,
        'extra': 2,
    },
    'newarray': {
        'opcode': 0xbc,
        'extra': 1,
    },
    'nop': {
        'opcode': 0x00,
        'extra': None,
    },
    'pop': {
        'opcode': 0x57,
        'extra': None,
    },
    'pop2': {
        'opcode': 0x58,
        'extra': None,
    },
    'putfield': {
        'opcode': 0xb5,
        'extra': 2,
    },
    'putstatic': {
        'opcode': 0xb3,
        'extra': 2,
    },
    'ret': {
        'opcode': 0xa9,
        'extra': 1,
    },
    'return': {
        'opcode': 0xb1,
        'extra': None,
    },
    'saload': {
        'opcode': 0x35,
        'extra': None,
    },
    'sastore': {
        'opcode': 0x56,
        'extra': None,
    },
    'sipush': {
        'opcode': 0x11,
        'extra': 2,
    },
    'swap': {
        'opcode': 0x5f,
        'extra': None,
    },
    'tableswitch': {
        'opcode': 0xaa,
        'extra': [16, None],
    },
    'wide': {
        'opcode': 0xc4,
        'extra': [3,5],
    },
}