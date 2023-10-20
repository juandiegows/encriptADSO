<?php


echo "Hi ADSO" . "<br>";;
echo "<br>";
//encriptando sin poder desencriptar

//md5 sha1 sha256
echo "Md5 : 12345 <br>";
echo "Md5 : " . md5("12345") . "<br>";
echo "Md5 : " . hash("md5", "12345") . "<br>";
echo "<br>";
echo "sha1 : 12345 <br>";
echo "sha1 : " . sha1("12345") . "<br>";
echo "sha1 : " . hash("sha1", "12345") . "<br>";
echo "<br>";
echo "sha256 : 12345 <br>";
echo "sha256 : " . hash("sha256", "12345") . "<br>";

// password_hash
echo "<br>";
$password = "12345";
$encriptada = password_hash($password, PASSWORD_BCRYPT);
echo "password_hash : 12345 <br>";
echo "password_hash : " . $encriptada . "<br>";

// comprobar contraseña

if (password_verify("12345", $encriptada)) {
    echo "la contraseña es igual";
} else {
    echo "la contraseña no es igual";
}
$clave = md5("12345");
if ($clave = md5("12345")) {
    echo "la contraseña es igual";
} else {
    echo "la contraseña no es igual";
}

// encriptar textos
echo "<br>";
echo "<br>";
echo "base64 : 12345 <br>";
$data =  base64_encode("sha256 : 5994471abb01112afcc18159f6cc74b4f511b99806da59b3caf5a9c173cacfc5");
echo "base64 encode: " . base64_encode("sha256 : 5994471abb01112afcc18159f6cc74b4f511b99806da59b3caf5a9c173cacfc5") . "<br>";
echo "base64 decode: " . base64_decode($data) . "<br>";


//encriptar contraseña con key
// https://www.php.net/manual/es/function.openssl-encrypt.php

$dato = "12345";
$key = "5994471abb01112afcc18159f6cc74b4f511b99806da59b3caf5a9c173cacfc5";
$iv = openssl_random_pseudo_bytes(16);
$encrypt = openssl_encrypt($dato, "aes-256-cbc", $key, 0, $iv);

echo "<br>";
echo "<br>";
echo "passwoopenssl_encrypt AES: 12345 <br>";
echo "passwoopenssl_encrypt AES : " . $encrypt . "<br>";
$descriptado = openssl_decrypt($encrypt, "aes-256-cbc", $key, 0, $iv);
echo "openssl_decrypt AES : " . $descriptado . "<br>";
