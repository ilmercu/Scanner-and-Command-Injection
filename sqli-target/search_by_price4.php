<?php
// import credentials
include('mysql_credentials.php');

// Open SQL Server connection
$con = new mysqli( $mysql_server, $mysql_user, $mysql_pass, $mysql_db );

// Check for SQL error
if ($con->connect_error) die ("Connection failed: " .$con->connect_error);

$max = $_GET['max'];

$query = "SELECT * FROM items WHERE price <= $max";
$result = $con->query($query);
echo $con->error;

while( $row = $result->fetch_assoc() ) {
  $name = $row["name"];
  echo " - $name <br/>";
}

$con->close();
