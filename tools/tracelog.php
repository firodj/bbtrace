<?php

define('PKT_CODE_TRACE', 1);

class TraceLog implements Serializable
{
    private $data;

    private $name;
    private $log_count;

    public $blocks;
    public $symbols;
    public $modules;
    public $imports;
    public $exceptions;
    public $functions;

    public function __construct($fname)
    {
        $fname = realpath($fname);

        if (preg_match('/^(.+\.log)\.(info|[0-9]+|func)$/', $fname, $matches)) {
            $fname = $matches[1];
        } else {
            throw new Exception("File name error: $fname");
        }

        $this->name = $fname;

        $this->data = (object)[
            'blocks' => [],
            'symbols' => [],
            'modules' => [],
            'imports' => [],
            'exceptions' => [],
            'functions' => [],
            'name' => $fname,
        ];

        $this->blocks = &$this->data->blocks;
        $this->symbols = &$this->data->symbols;
        $this->modules = &$this->data->modules;
        $this->imports = &$this->data->imports;
        $this->exceptions = &$this->data->exceptions;
        $this->functions = &$this->data->functions;
        $this->name = &$this->data->name;
    }

    public function getLogCount()
    {
        if (!isset($this->log_count)) {
            $log_count = 0;
            for (;;$log_count++) {
                $fpath = sprintf("%s.%04d", $this->name, $log_count+1);
                if (!is_file($fpath)) break;
            }
            $this->log_count = $log_count;
        }
        return $this->log_count;
    }

    /* callback return non zero to stop */
    public function parseLog($log_nbr, $pkt_start, $callback)
    {
        $fpath = sprintf("%s.%04d", $this->name, $log_nbr);
        fprintf(STDERR, "Open: %s\n", $fpath);

        $fp = fopen($fpath, 'rb');
        $n = 0;
        $ret = null;

        while (!feof($fp)) {
            $data = fread($fp, (4+8+4));
            if (!feof($fp)) {
                $data = unpack('Lcode/Qts/Lthread', $data);
            } else break;

            if ($data['code'] == PKT_CODE_TRACE) {
                $n++;

                $header = array_merge($data, unpack('Lsize', fread($fp, 4)));
                $header['pkt_no'] = $n;

                if ($pkt_start && $n < $pkt_start) {
                    fseek($fp, $header['size']*4, SEEK_CUR);
                } else {
                    $raw_data = fread($fp, $header['size']*4);
                    $ret = $callback($header, $raw_data);
                    if ($ret) break;
                }
            }
        }
        fclose($fp);
        return $ret;
    }

    protected function saveInfo($o)
    {
        if (isset($o['module_start'])) {
            $this->modules[ hexdec($o['module_start']) ] = $o;
        } elseif (isset($o['block_entry'])) {
            $this->blocks[ hexdec($o['block_entry']) ] = $o;
        }
        elseif (isset($o['symbol_entry'])) {
            $this->symbols[ hexdec($o['symbol_entry']) ] = $o;
        }
        elseif (isset($o['exception_code'])) {
            $this->exceptions[ hexdec($o['exception_address']) ] = $o;
        }
        elseif (isset($o['import_module_name'])) {
            $this->imports[$o['symbol_name']] = $o;
        }
        elseif (isset($o['function_entry'])) {
            $this->functions[ hexdec($o['function_entry']) ] = $o;
        }
        else {
            fprintf(STDERR, "Bad Info:%s\n", json_encode($o));
        }
    }

    public static function parseJson($fpath, Closure $save_cb)
    {
        fprintf(STDERR, "Open: %s\n", $fpath);

        $fp = fopen($fpath, 'r');
        $STATE_ARRAY = false;
        $STATE_OBJECT = false;
        $s = null;

        while (!feof($fp)) {
            $data = fgets($fp);
            $data = preg_replace('/\r\n/', '', $data);

            if ($STATE_OBJECT) {
                $s .= $data;
                if (preg_match('/\},?$/', $data)) {
                    $STATE_OBJECT = false;

                    $s = trim($s, "\r\n, ");
                    $o = json_decode($s, true);
                    if (!empty($o)) {
                        $save_cb($o);
                    }
                }
            } elseif ($STATE_ARRAY) {
                if (preg_match('/^\{/', $data)) {
                    $STATE_OBJECT = true;
                    $s = $data;
                }
                if ($STATE_OBJECT && preg_match('/\},?$/', $data)) {
                    $STATE_OBJECT = false;

                    $s = trim($s, "\r\n, ");
                    $o = json_decode($s, true);
                    if (!empty($o)) {
                        $save_cb($o);
                    }
                }
                if (preg_match('/\],?$/', $data)) {
                    $STATE_ARRAY = false;
                }
            } else {
                if (preg_match('/^\[/', $data)) {
                    $STATE_ARRAY = true;
                }
                if ($STATE_ARRAY && preg_match('/\],?$/', $data)) {
                    $STATE_ARRAY = false;
                }
            }
        }

    }

    public function parseInfo()
    {
        $fpath = sprintf("%s.info", $this->name);
        self::parseJson($fpath, function($o) {
            $this->saveInfo($o);
        });

        fprintf(STDERR, "Blocks: %d\nSymbols: %d\n", count($this->blocks), count($this->symbols));
        fprintf(STDERR, "Modules: %d\nImports: %d\n", count($this->modules), count($this->imports));
        fprintf(STDERR, "Exceptions: %d\n", count($this->exceptions));
    }

    public function parseFunc()
    {
        $fpath = sprintf("%s.func", $this->name);
        self::parseJson($fpath, function($o) {
            $this->saveInfo($o);
        });
        fprintf(STDERR, "Functions: %d\n", count($this->functions));
    }

    public function serialize(): string
    {
        return serialize($this->data);
    }

    public function unserialize($serialized)
    {
        $this->data = unserialize($serialized);

        $this->blocks = &$this->data->blocks;
        $this->symbols = &$this->data->symbols;
        $this->modules = &$this->data->modules;
        $this->imports = &$this->data->imports;
        $this->exceptions = &$this->data->exceptions;
        $this->functions = &$this->data->functions;
        $this->name = &$this->data->name;
    }

    public static function main($argv)
    {
        if (count($argv) <= 1) {
            fprintf(STDERR, "Syntax: %s <file.log.info>\n", $argv[0]);
            return false;
        }

        $trace_log = new TraceLog($argv[1]);
        $trace_log->parseInfo();
        $trace_log->parseFunc();

        return $trace_log;
    }
}

if (basename(__FILE__) == basename($_SERVER["SCRIPT_FILENAME"])) {
    $trace_log = TraceLog::main($argv);

    $trace_log2 = unserialize( serialize($trace_log) );
    unset($trace_log);

    for ($i=1; $i<=$trace_log2->getLogCount(); $i++) {
        $trace_log2->parseLog($i, 0, function($header, $raw_data) use ($trace_log2) {
            fprintf(STDERR, "%d.", $header['pkt_no']);

            $data = unpack('V*', $raw_data);
            foreach($data as $block_id) {
                if (isset($trace_log2->functions[$block_id])) {
                    $func = $trace_log2->functions[$block_id];
                    echo $func['function_name'].PHP_EOL;
                }
                if (isset($trace_log2->blocks[$block_id])) {
                    $block = $trace_log2->blocks[$block_id];
                    echo "\t".dechex($block_id).PHP_EOL;
                } else if (isset($trace_log2->symbols[$block_id])) {
                    $sym = $trace_log2->symbols[$block_id];
                    echo "\t\t".dechex($block_id)." ".$sym['symbol_name'].PHP_EOL;
                } else {
                    echo sprintf("Unknown: 0x%08x\n", $block_id);
                }
            }
        });
    }
}
