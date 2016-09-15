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
            Message("{\"entry\":\"0x%x\",\"end\":\"0x%x\",\"name\":\"%s\"},\n", ea, end, str);
        }

        ea = NextFunction(ea);
    }
}

static main() 
{
    FuncDump(0x0);
}