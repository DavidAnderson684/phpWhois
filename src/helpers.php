 <?php

if( !function_exists('str_starts_with') ){
    function str_starts_with( string $haystack, string $needle ): bool
    {
        return strpos($haystack,$needle) === 0;
    }
}

if( !function_exists('str_ends_with') ){
    function str_ends_with( string $haystack, string $needle ): bool
    {
        $needle_len = strlen($needle);
        return ($needle_len === 0 || 0 === substr_compare($haystack, $needle, -$needle_len));
    }
}

if( !function_exists('str_contains') ){
    function str_contains($haystack, $needle): bool
    {
        return $needle !== '' && stripos($haystack, $needle) !== false;
    }
}