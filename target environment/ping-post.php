<?php

$host = $_POST['host'];

system("ping -c 3 $host");
