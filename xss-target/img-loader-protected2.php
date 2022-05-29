<?php

$target = $_GET['target'];
$target = htmlspecialchars($target, ENT_QUOTES);
echo "<img src='$target'/>";

