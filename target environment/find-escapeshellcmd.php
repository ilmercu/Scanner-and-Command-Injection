<?php

$input = $_GET['input'];

system(escapeshellcmd("find . -name $input"));
