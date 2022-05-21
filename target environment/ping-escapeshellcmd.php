<?php

$host = $_GET['host'];

system(escapeshellcmd("ping -c 3 $host"));
