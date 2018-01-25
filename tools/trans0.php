<?php

require 'JsonParser.php';

$fpath = $argv[1];

if (!preg_match('/\.log\.info$/', $fpath)) die('should be .log.info');

$fout = preg_replace('/\.log\.info$/', '${0}.log.block', $fpath);
fprintf(STDERR, "Save block: %s\n", $fout);

//---
echo <<<EOS
#include <idc.idc>

static list_cref(ea)
{
    auto x;
    msg("\\n*** Code references from " + atoa(ea) + "\\n");
    for ( x=get_first_cref_from(ea); x != BADADDR; x=get_next_cref_from(ea,x) ) {
        msg(atoa(ea) + " refers to " + atoa(x) + "\\n");
    }
}

static color_instr(ea, maxea, col)
{
    auto x;
    msg("\\n*** Coloring instructions from " + atoa(ea) + "\\n");
    for ( x=ea; x != BADADDR; x=next_head(x,maxea) ) {
        set_color(x, CIC_ITEM, col);
    }
}

static main()
{

EOS;

$fp = fopen($fout, 'w');

(new JsonParser($fpath))->parse(function($o) use ($fp) {
    if ($o['block_entry']) {
        fprintf($fp, '"%s", "%s", "%s"'.PHP_EOL, $o['block_entry'], $o['block_end'], $o['module_start_ref']);
        $ea = $o['block_entry'];
        $maxea = $o['block_end'];

//--
echo <<<EOS
    color_instr($ea, $maxea, 0xccffff);

EOS;
    }
});

fclose($fp);

$fpath2 = preg_replace('/\.log\.info$/', '.log.flow', $fpath);

fprintf(STDERR, "Open flow: %s\n", $fpath2);
$fp = fopen($fpath2, 'r');

while (($data = fgetcsv($fp, 100, ",")) !== FALSE) {
    $block_addr = $data[0];
    $last_block_addr = $data[1];

    // TODO:
    fprintf(STDERR, "%s -> %s\n", $last_block_addr, $block_addr);
}

fclose($fp);
//---
echo <<<EOS
}
EOS;
