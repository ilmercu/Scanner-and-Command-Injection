<?php

$target = $_GET['target'];
$target = htmlspecialchars($target);
echo "<img src='$target'/>";

