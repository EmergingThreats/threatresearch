def parse_ProtobufCFieldDescriptor(addr, index):
    entry_addr = addr+48*index
    
    name_addr = get_wide_dword(entry_addr)
    name = get_strlit_contents(name_addr, -1, STRTYPE_C)
    
    id = get_wide_dword(entry_addr+0x4)
    
    offset = get_wide_dword(entry_addr+0x14)
    
    descriptor = get_wide_dword(entry_addr+0x18)
    
    if descriptor:
        print("id: %d, struct offset 0x%x: %s (descriptor: 0x%x)" % (id, offset, name.decode(), descriptor))
    else:
        print("id: %d, struct offset 0x%x: %s" % (id, offset, name.decode()))
    
    
def parse_ProtobufCMessageDescriptor(addr):
    print("*"*60)
    
    magic = get_wide_dword(addr)
    if magic != 0x28aaeef9:
        print("bad magic")
        return
        
    c_name_addr = get_wide_dword(addr+0xc)
    c_name = get_strlit_contents(c_name_addr, -1, STRTYPE_C)
    print("struct name: %s" % c_name.decode())
    
    sizeof_message = get_wide_dword(addr+0x14)
    print("struct size: %d" % sizeof_message)
    
    n_fields = get_wide_dword(addr+0x18)
    print("num fields: %d" % n_fields)
    
    fields_addr = get_wide_dword(addr+0x1c)
    for i in range(n_fields):
        parse_ProtobufCFieldDescriptor(fields_addr, i)
        
    print("*"*60)
            
parse_ProtobufCMessageDescriptor(here())
#parse_ProtobufCFieldDescriptor(here(), 0)
