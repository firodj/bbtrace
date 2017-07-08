<?php

define('PKT_CODE_TRACE', 1);

class TraceLog implements Serializable
{
    private $data;

    private $name;
    private $log_count;

    private $blocks;
    private $symbols;
    private $modules;
    private $imports;
    private $exceptions;
    private $functions;

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

    public function parseLog($log_nbr)
    {
        $fpath = sprintf("%s.%04d", $this->name, $log_nbr);
        echo "Open: $fpath\n";

        $fp = fopen($fpath, 'rb');
        while (!feof($fp)) {
            $data = fread($fp, (4+8+4));
            if (!feof($fp)) {
                $data = unpack('Lcode/Qts/Lthread', $data);
            } else break;

            if ($data['code'] == PKT_CODE_TRACE) {
                $header = array_merge($data, unpack('Lsize', fread($fp, 4)));
                print_r($header);

                $data = unpack('L*', fread($fp, $header['size']*4));
                foreach($data as $block_id) {
                    $block_id = sprintf("0x%08x", $block_id);
                    if (isset($this->blocks[$block_id])) {
                    } else if (isset($this->symbols[$block_id])) {
                    } else {
                        echo "Unknown:\n";
                        print_r($block_id);
                    }
                }
            }
        }
        fclose($fp);
    }

    protected function saveInfo($o)
    {
        if (isset($o['module_start'])) {
            $this->modules[$o['module_start']] = $o;
        } elseif (isset($o['block_entry'])) {
            $this->blocks[$o['block_entry']] = $o;
        }
        elseif (isset($o['symbol_entry'])) {
            $this->symbols[$o['symbol_entry']] = $o;
        }
        elseif (isset($o['exception_code'])) {
            $this->exceptions[$o['exception_address']] = $o;
        }
        elseif (isset($o['import_module_name'])) {
            $this->imports[$o['symbol_name']] = $o;
        }
        elseif (isset($o['function_entry'])) {
            $this->functions[$o['function_entry']] = $o;
        }
        else {
            echo "Bad:\n";
            print_r($o);
        }
    }

    public static function parseJson($fpath, Closure $save_cb)
    {
        echo "Open: $fpath\n";

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

        printf("Blocks: %d\nSymbols: %d\n", count($this->blocks), count($this->symbols));
        printf("Modules: %d\nImports: %d\n", count($this->modules), count($this->imports));
        printf("Exceptions: %d\n", count($this->exceptions));
    }

    public function parseFunc()
    {
        $fpath = sprintf("%s.func", $this->name);
        self::parseJson($fpath, function($o) {
            $this->saveInfo($o);
        });
        printf("Functions: %d\n", count($this->functions));
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
            echo "Syntax: $argv[0] <file.log.info>\n";
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

    for ($i=1; $i<=$trace_log2->getLogCount(); $i++) {
        $trace_log2->parseLog($i);
    }
}
