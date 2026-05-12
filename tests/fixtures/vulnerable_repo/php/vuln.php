<?php
// Intentionally vulnerable PHP fixture (for Suzaku Compass tests).
// DO NOT use this code. It exists only as scanner bait.

function unsafe_eval($code) {
    eval($code);
}

function unsafe_unserialize($data) {
    $obj = unserialize($data);
    return $obj;
}

function unsafe_include() {
    include $_GET['template'];
}

function unsafe_exec($user_cmd) {
    system($user_cmd);
    shell_exec("ls " . $user_cmd);
}

function unsafe_extract() {
    extract($_POST);
}

// preg_replace with /e modifier (deprecated, but still found in old code)
function unsafe_preg($input) {
    return preg_replace('/foo(.*)/e', 'strtoupper($1)', $input);
}
