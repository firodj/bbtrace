#include <idc.idc>

static FuncDump(start)
{
    auto ea, end, str, mod, segea;

    ea = start;

    while( ea != BADADDR )
    {
        str = GetFunctionName(ea);
        if( str != 0 )
        {
            end = GetFunctionAttr(ea, FUNCATTR_END);
            segea = SegStart(ea);
            Message("{\n\t\"function_entry\":\"0x%08x\",\n\t\"function_end\":\"0x%08x\",\n\t\"function_name\":\"%s\",\n\t\"module_start_ref\":\"0x%08x\"\n},\n", ea, end, str, segea);
        }

        ea = NextFunction(ea);
    }
}

static main() 
{
    Message("[\n");
    FuncDump(0x0);
    Message("{}\n]");
}
