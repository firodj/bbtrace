#include <idc.idc>

// IDA 7.0

static func_dump_all(start, fhandle)
{
    auto ea, end, str, mod, segea;

    ea = start;

    while( ea != BADADDR )
    {
        str = get_func_name(ea);
        if( str != 0 )
        {
            end = get_func_attr(ea, FUNCATTR_END);
            segea = get_segm_start(ea);
            fprintf(fhandle, "{\n\t\"function_entry\":\"0x%08x\",\n\t\"function_end\":\"0x%08x\",\n\t\"function_name\":\"%s\",\n\t\"module_start_ref\":\"0x%08x\"\n},\n", ea, end, str, segea);
        }

        ea = get_next_func(ea);
    }
}

static main() 
{
	auto fname, fhandle;
	
	fname = ask_file(1, "*.func", "Output file?");

	fhandle = fopen(fname, "w");	
    fprintf(fhandle, "[\n");
    func_dump_all(0x0, fhandle);
    fprintf(fhandle, "{}\n]");
	fclose(fhandle);
	
	Message("Done: %s!\n", fname);
}
