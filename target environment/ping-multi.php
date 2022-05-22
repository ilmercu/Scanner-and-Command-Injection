<?php

$host = $_GET['host'];

system("ping -c 3 $host");

$host_2 = $_GET['host_2'];

system("ping -c 3 $host_2");
