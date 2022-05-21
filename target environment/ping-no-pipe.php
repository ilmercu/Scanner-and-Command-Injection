<?php

$host = $_GET['host'];

if (strpos($host, "|") > 0) { die('NO HAX PLZ'); }

system("ping -c 3 $host");
