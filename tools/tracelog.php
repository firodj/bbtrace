<?php

define('PKT_CODE_TRACE', 1);

class TraceLog
{
    private $name;
    private $log_count;
    private $blocks;
    private $symbols;
    private $modules;
    private $imports;
    private $exceptions;

    public function __construct($name)
    {
        $this->name = $name;
    }

    public function getLogCount()
    {
        if (is_null($this->log_count)) {
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

    protected function saveInfo($json)
    {
        $json = trim($json, "\r\n, ");
        $o = json_decode($json, true);
        if (empty($o)) return;

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
        else {
            echo "Bad:\n";
            print_r($o);
        }
    }

    public function parseInfo()
    {
        $fpath = sprintf("%s.info", $this->name);
        echo "Open: $fpath\n";

        $fp = fopen($fpath, 'r');
        $STATE_ARRAY = false;
        $STATE_OBJECT = false;
        $s = null;

        while (!feof($fp)) {
            $data = fgets($fp);

            if ($STATE_OBJECT) {
                $s .= $data;
                if (preg_match('/\},?$/', $data)) {
                    $STATE_OBJECT = false;
                    $this->saveInfo($s);
                }
            } elseif ($STATE_ARRAY) {
                if (preg_match('/^\{/', $data)) {
                    $STATE_OBJECT = true;
                    $s = $data;
                }
                if ($STATE_OBJECT && preg_match('/\},?$/', $data)) {
                    $STATE_OBJECT = false;
                    $this->saveInfo($s);
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

        printf("Blocks: %d\nSymbols: %d\n", count($this->blocks), count($this->symbols));
        printf("Modules: %d\nImports: %d\n", count($this->modules), count($this->imports));
        printf("Exceptions: %d\n", count($this->exceptions));
    }

    public static function main($argv)
    {
        if (count($argv) <= 1) {
            echo "Syntax: $argv[0] <file.log.info>\n";
            return false;
        }

        $fname = $argv[1];
        if (preg_match('/^(.+\.log)\.info$/', $fname, $matches)) {
            $fname = $matches[1];
        } else {
            echo "Error: file name not match <file.log.info>\n";
            return false;
        }

        $trace_log = new TraceLog($fname);
        $trace_log->parseInfo();
        for ($i=1; $i<=$trace_log->getLogCount(); $i++) {
            $trace_log->parseLog($i);
        }
        return $trace_log;
    }
}

$trace_log = TraceLog::main($argv);
