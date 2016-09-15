#include <idc.idc>

static FuncDump(start)
{
    auto ea, end, str;

    ea = start;

    while( ea != BADADDR )
    {
        str = GetFunctionName(ea);
        if( str != 0 )
        {
            end = GetFunctionAttr(ea, FUNCATTR_END);
            Message("{\"function_entry\":\"0x%x\",\"function_end\":\"0x%x\",\"function_name\":\"%s\"},\n", ea, end, str);
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