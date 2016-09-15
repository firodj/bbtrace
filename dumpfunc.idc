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
            Message("functions[0x%x] = Function(0x%x, 0x%x, '%s')\n", ea, ea, end, str);
        }

        ea = NextFunction(ea);
    }
}

static main() 
{
    FuncDump(0x0);
}