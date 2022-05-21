<?php

$host = $_GET['host'];

system("ping -c 3 $host");
