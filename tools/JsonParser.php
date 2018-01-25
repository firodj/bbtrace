<?php

class JsonParser
{
    private $file_name;

    public function __construct($file_name)
    {
        $this->file_name = $file_name;
    }

    public function parse(Closure $callback)
    {
        fprintf(STDERR, "Open: %s\n", $this->file_name);

        $fp = fopen($this->file_name, 'r');

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
                        $callback($o);
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
                        $callback($o);
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

        fclose($fp);
    }
}
