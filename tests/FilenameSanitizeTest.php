<?php

declare(strict_types=1);

// Shortcut for directory separator.
// If is test run in Windows OS => '\'. In Unix OS => '/'.
define('DS', DIRECTORY_SEPARATOR);

use OndrejVrto\FilenameSanitize\FilenameSanitize;

test('filename', function (string $input, string $result): void {
    $output = (new FilenameSanitize($input))->get();

    expect($output)->toBe($result);

    // short static format
    $output2 = FilenameSanitize::of($input)->get();

    expect($output2)->toBe($result);
})->with([
    'Ok'                              => ['file-name.ext'             , 'file-name.ext'],
    'Zero'                            => ['0'                         , '0'],
    'Zero with extension'             => ['0.ext'                     , '0.ext'],
    'Zero number in extension'        => ['file.0'                    , 'file.0'],
    'Multibyte characters'            => ['火|车..票'                  , '火-车.票'],
    'Only Extencion'                  => ['.github'                   , '.github'],
    'Only name'                       => ['filename'                  , 'filename'],
    'Multi Extension'                 => ['.env.test'                 , '.env.test'],
    'Default separator in begining'   => ['-file#name.ext'            , 'file-name.ext'],
    'Upper case with one spane'       => ['File NaME.Zip'             , 'file-name.zip'],
    'Multiple underscores'            => ['file___name.zip'           , 'file-name.zip'],
    'Multiple dashes'                 => ['file---name.zip'           , 'file-name.zip'],
    'Multiple dots'                   => ['file...name..zip'          , 'file.name.zip'],
    'File system reserved characters' => ['file<->name":.zip:'        , 'file-name.zip'],
    'URL unsafe characters'           => ['~file-{name}^.[zip]'       , 'file-name.zip'],
    'Multiple spaces'                 => ['   file  name  .   zip'    , 'file-name.zip'],
    'Chars in start and end'          => ['[file~name].{jpg}'         , 'file-name.jpg'],
    'Reduce consecutive characters'   => ['file--.--.-.--name.zip'    , 'file.name.zip'],
    'URI reserved characters'         => ['file-name|#[]&@()+,;=.zip' , 'file-name.zip'],
    'js script'                       => ['<script>alert(1);</script>', 'script'],
    'Non-breaking space'              => ['file' . mb_chr(0xA0, 'UTF-8') . 'name.ext', 'file-name.ext'],
    'Null character'                  => ['file' . mb_chr(0x00, 'UTF-8') . 'name.ext', 'file-name.ext'],
    'php function' => [
        '<?php malicious_function(); ?>`rm -rf `',
        'php-malicious-function-rm-rf'
    ],
    'special char 0' => [
        'On | Off Again: My Journey to Stardom.jpg' . chr(0),
        'on-off-again-my-journey-to-stardom.jpg'
    ],
    'long filename to max 255 chars' => [
        '12345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890'
        . '12345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890'
        . '12345678901234567890123456789012345678901234567890123456789012345678901234567890.zip',

        '12345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890'
        . '12345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890'
        . '1234567890123456789012345678901.zip'
    ],
]);

test('directory', function (string $input, string $result1, string $result2): void {
    $output1 = FilenameSanitize::of($input)
        ->get();

    expect($output1)->toBe($result1);

    $output2 = FilenameSanitize::of($input)
        ->withSubdirectory()
        ->get();

    expect($output2)->toBe($result2);
})->with([
    'Basic'                   => ['\dir\dir\file-name.ext'        , 'file-name.ext'    , DS . 'dir' . DS . 'dir' . DS . 'file-name.ext'],
    'Windows'                 => ['C:\dir\dir\file-name.ext'      , 'file-name.ext'    , 'C' . DS . 'dir' . DS . 'dir' . DS . 'file-name.ext'],
    'Multibyte characters'    => ['火/车~车..票'                    , '车-车.票'         , '火' . DS . '车-车.票'],
    'Only Extencion'          => ['/dir\dir/.github'              , '.github'          , DS . 'dir' . DS . 'dir' . DS . '.github'],
    'Only name'               => ['/dir\dir/filename'             , 'filename'         , DS . 'dir' . DS . 'dir' . DS . 'filename'],
    'Multi Extension'         => ['/dir\dir/.env.test'            , '.env.test'        , DS . 'dir' . DS . 'dir' . DS . '.env.test'],
    'URL unsafe characters'   => ['~dir/-{d}i^r/filename.[zip]'   , 'filename.zip'     , 'dir' . DS . 'd-i-r' . DS . 'filename.zip'],
    'URI reserved characters' => ['dir\|#[\file]&n@a(m)e+,;=.zip' , 'file-n-a-m-e.zip' , 'dir' . DS . 'file-n-a-m-e.zip'],
    'relative path'           => ['./..\dir/file-name.zip'        , 'file-name.zip'    , '.' . DS . '..' . DS . 'dir' . DS . 'file-name.zip'],
    'relative path 2'         => ['~/../..\dir/../file-name.zip'  , 'file-name.zip'    , '~' . DS . '..' . DS . '..' . DS . 'dir' . DS . '..' . DS . 'file-name.zip'],
    'script'                  => ['<script>alert(1);</script>'    , 'script'           , 'script-alert-1' . DS . 'script'],
]);

test('prefix and suffix', function (string $input, string $result1, string $result2): void {
    $output1 = FilenameSanitize::of($input)
        ->widthFilenamePrefix('prefix')
        ->widthFilenameSuffix('suffix')
        ->get();

    expect($output1)->toBe($result1);

    $output2 = FilenameSanitize::of($input)
        ->widthFilenamePrefix('prefix')
        ->widthFilenameSuffix('suffix')
        ->withSubdirectory()
        ->get();

    expect($output2)->toBe($result2);
})->with([
    'Basic'                   => ['\dir\dir\file-name.ext'        , 'prefix-file-name-suffix.ext'    , DS . 'dir' . DS . 'dir' . DS . 'prefix-file-name-suffix.ext'],
    'Windows'                 => ['C:\dir\dir\file-name.ext'      , 'prefix-file-name-suffix.ext'    , 'C' . DS . 'dir' . DS . 'dir' . DS . 'prefix-file-name-suffix.ext'],
    'Multibyte characters'    => ['火/车~车..票'                    , 'prefix-车-车-suffix.票'          , '火' . DS . 'prefix-车-车-suffix.票'],
    'Only Extencion'          => ['/dir\dir/.github'              , 'prefix--suffix.github'          , DS . 'dir' . DS . 'dir' . DS . 'prefix--suffix.github'],
    'Only name'               => ['/dir\dir/filename'             , 'prefix-filename-suffix'         , DS . 'dir' . DS . 'dir' . DS . 'prefix-filename-suffix'],
    'Multi Extension'         => ['/dir\dir/.env.test'            , 'prefix-.env-suffix.test'        , DS . 'dir' . DS . 'dir' . DS . 'prefix-.env-suffix.test'],
    'URL unsafe characters'   => ['~dir/-{d}i^r/filename.[zip]'   , 'prefix-filename-suffix.zip'     , 'dir' . DS . 'd-i-r' . DS . 'prefix-filename-suffix.zip'],
    'URI reserved characters' => ['dir\|#[\file]&n@a(m)e+,;=.zip' , 'prefix-file-n-a-m-e-suffix.zip' , 'dir' . DS . 'prefix-file-n-a-m-e-suffix.zip'],
]);

test('extension', function (string $input, string $result1, string $result2, string $result3, string $result4): void {
    $output1 = FilenameSanitize::of($input)
        ->withNewExtension('webp')
        ->get();

    expect($output1)->toBe($result1);

    $output2 = FilenameSanitize::of($input)
        ->addActualExtensionToFilename()
        ->get();

    expect($output2)->toBe($result2);

    $output3 = FilenameSanitize::of($input)
        ->addActualExtensionToFilename()
        ->withNewExtension('webp')
        ->get();

    expect($output3)->toBe($result3);

    $output4 = FilenameSanitize::of($input)
        ->addActualExtensionToFilename()
        ->widthFilenameSuffix('suffix')
        ->withNewExtension('webp')
        ->get();

    expect($output4)->toBe($result4);
})->with([
    'Basic'                   => ['\dir\dir\file-name.ext'       , 'file-name.webp'   , 'file-name-ext.ext'   , 'file-name-ext.webp'   , 'file-name-suffix-ext.webp'],
    'Multibyte characters'    => ['火/车~车..票'                  , '车-车.webp'        , '车-车-票.票'           , '车-车-票.webp'         , '车-车-suffix-票.webp'],
    'Only Extencion'          => ['/dir\dir/.github'             , '.webp'            , '-github.github'      , '-github.webp'         , '-suffix-github.webp'],
    'Only name'               => ['/dir\dir/filename'            , 'filename.webp'    , 'filename'            , 'filename.webp'        , 'filename-suffix.webp'],
    'Multi Extension'         => ['/dir\dir/.env.test'           , '.env.webp'        , '.env-test.test'      , '.env-test.webp'       , '.env-suffix-test.webp'],
    'URL unsafe characters'   => ['~dir/-{d}i^r/filename.[zip]'  , 'filename.webp'    , 'filename-zip.zip'    , 'filename-zip.webp'    , 'filename-suffix-zip.webp'],
    'URI reserved characters' => ['dir\|#[\file]&n@a(m)e+,;=.zip', 'file-n-a-m-e.webp', 'file-n-a-m-e-zip.zip', 'file-n-a-m-e-zip.webp', 'file-n-a-m-e-suffix-zip.webp'],
]);

test('separator', function (string $separator, string $result): void {
    $output = FilenameSanitize::of('file~name.ext')
        ->customSeparator($separator)
        ->get();

    expect($output)->toBe($result);
})->with([
    // Not alowed characters
    'Empty'                         => [''  , 'file-name.ext'],
    'Dot'                           => ['.' , 'file-name.ext'],
    'Dots'                          => ['..', 'file-name.ext'],
    'Multi byte char'               => ['票', 'file-name.ext'],
    'Default separator'             => ['-' , 'file-name.ext'],
    'Not alowed Hashtag'            => ['#' , 'file-name.ext'],
    'Not alowed Backslash'          => ['/' , 'file-name.ext'],
    'Not alowed Non-breaking space' => [mb_chr(0xA0, 'UTF-8'), 'file-name.ext'],
    'Not alowed Nul character'      => [mb_chr(0x00, 'UTF-8'), 'file-name.ext'],
    // Alowed characters
    'Spaces'                            => ['   ', 'file   name.ext'],
    'String'                            => ['xxx', 'filexxxname.ext'],
    'Zero'                              => ['0'  , 'file0name.ext'],
    'Numbers'                           => ['012', 'file012name.ext'],
    'Under dash'                        => ['___', 'file___name.ext'],
    'Combine alowed chars'              => ['_--', 'file_--name.ext'],
    'Combination bad and aloowed chars' => ['?>_', 'file_name.ext'],
    // Strange behavior: Individual separator characters are removed from the beginning and end of the file name and extension.
    'String with same letter'             => ['ef', 'ileefnam.xt'],
    'String with same letter in end'      => ['e', 'fileenam.xt'],
    'String with same letter in begining' => ['f', 'ilefname.ext'],
]);

test('lowercase letters', function (string $input, string $result): void {
    $output = FilenameSanitize::of($input)
        ->disableLowerCase()
        ->get();

    expect($output)->toBe($result);
})->with([
    'All upper case letters'   => ['FILE*NAME.EXT' , 'FILE-NAME.EXT'],
    'All lower case letters'   => ['file*name.ext' , 'file-name.ext'],
    'Combination case letters' => ['FilE*NamE.Ext' , 'FilE-NamE.Ext'],
]);

test('base directory', function (string $baseDirectory, string $filename, string $result): void {
    $output = FilenameSanitize::of($filename)
        ->withBaseDirectory($baseDirectory)
        ->withSubdirectory()
        ->get();

    expect($output)->toBe($result);
})->with([
    'Basic'                => ['C:/foo/bar'   , '\..\dir\file-name.zip'  , "C:" . DS . "foo" . DS . "bar" . DS . ".." . DS . "dir" . DS . "file-name.zip"],
    'Without separator'    => ['C:/foo/bar'   , '..\dir\file-name.zip'   , "C:" . DS . "foo" . DS . "bar" . DS . ".." . DS . "dir" . DS . "file-name.zip"],
    'Multiple separator 1' => ['C:/foo/bar/'  , '\..\dir\file-name.zip'  , "C:" . DS . "foo" . DS . "bar" . DS . ".." . DS . "dir" . DS . "file-name.zip"],
    'Multiple separator 2' => ['C:/foo/bar/'  , '/..\dir\file-name.zip'  , "C:" . DS . "foo" . DS . "bar" . DS . ".." . DS . "dir" . DS . "file-name.zip"],
    'Multiple separator 3' => ['C:/foo/bar\\' , '\..\dir\file-name.zip'  , "C:" . DS . "foo" . DS . "bar" . DS . ".." . DS . "dir" . DS . "file-name.zip"],
    'Multiple separator 4' => ['C:/foo/bar\\' , '\..\dir\file-name.zip'  , "C:" . DS . "foo" . DS . "bar" . DS . ".." . DS . "dir" . DS . "file-name.zip"],
    'Unix root'            => ['\tmp\foo\\'   , 'bar\file-name.zip'      , DS . "tmp" . DS . "foo" . DS . "bar" . DS . "file-name.zip"],
    'Bad chars in base'    => ['\t#mp\f&oo\\' , 'bar\file-name.zip'      , DS . "t#mp" . DS . "f&oo" . DS . "bar" . DS . "file-name.zip"],
]);

test('directory to filename', function (): void {
    $output = FilenameSanitize::of('C:/foo/bar/file-name.zip')
        ->addSubdirectoryToFilename()
        ->get();
    expect($output)->toBe('c-foo-bar-file-name.zip');

    $output = FilenameSanitize::of('foo/bar/file-name.zip')
        ->addSubdirectoryToFilename()
        ->withSubdirectory()
        ->get();
    expect($output)->toBe("foo" . DS . "bar" . DS . "foo-bar-file-name.zip");

    $output = FilenameSanitize::of('foo/bar/file-name.zip')
        ->addActualExtensionToFilename()
        ->widthFilenamePrefix('prefix')
        ->widthFilenameSuffix('surfix')
        ->withBaseDirectory('C:\baz')
        ->addSubdirectoryToFilename()
        ->withNewExtension('webp')
        ->withSubdirectory()
        ->get();

    expect($output)->toBe("C:" . DS . "baz" . DS . "foo" . DS . "bar" . DS . "prefix-foo-bar-file-name-surfix-zip.webp");

    $output = FilenameSanitize::of('\foo2\bar2\baz2\long-file-name-'
    . '1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890'
    . '1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890'
    . '123456789012345678901234567890123456789012345678901234567890.zip')
        ->widthFilenamePrefix('looong-prefix')
        ->widthFilenameSuffix('looong-surfix')
        ->withBaseDirectory('C:/foo/bar/baz')
        ->addActualExtensionToFilename()
        ->withNewExtension('webp')
        ->addSubdirectoryToFilename()
        ->withSubdirectory()
        ->get();

    expect($output)->toBe("C:" . DS . "foo" . DS . "bar" . DS . "baz" . DS . "foo2" . DS . "bar2" . DS . "baz2" . DS
    . "looong-prefix--foo2-bar2-baz2-long-file-name-"
    . "12345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    . "12345678901234567890123456789012345678901234567890123456789012345678901234567-looong-surfix-zip.webp");
});

test('test from another package', function (string $filename, string $result1, string $result2): void {
    $output1 = FilenameSanitize::of($filename)
        ->get();

    expect($output1)->toBe($result1);

    $output2 = FilenameSanitize::of($filename)
        ->withSubdirectory()
        ->get();

    expect($output2)->toBe($result2);
})->with([
    "résumé"                            =>  ["résumé"                            , "résumé"                , "résumé"],
    "hello\u{0000}world"                =>  ["hello\u{0000}world"                , "hello-world"           , "hello-world"],
    "hello [enter] world"               =>  ["hello\nworld"                      , "hello-world"           , "hello-world"],
    "semi;colon.js"                     =>  ["semi;colon.js"                     , "semi-colon.js"         , "semi-colon.js"],
    ";leading-semi.js"                  =>  [";leading-semi.js"                  , "leading-semi.js"       , "leading-semi.js"],
    "slash\\.js"                        =>  ["slash\\.js"                        , ".js"                   , "slash" . DS . ".js"],
    "slash/.js"                         =>  ["slash/.js"                         , ".js"                   , "slash" . DS . ".js"],
    "col:on.js"                         =>  ["col:on.js"                         , "col-on.js"             , "col-on.js"],
    "star*.js"                          =>  ["star*.js"                          , "star.js"               , "star.js"],
    "question?.js"                      =>  ["question?.js"                      , "question.js"           , "question.js"],
    "quote\".js"                        =>  ["quote\".js"                        , "quote.js"              , "quote.js"],
    "singlequote'.js"                   =>  ["singlequote'.js"                   , "singlequote.js"        , "singlequote.js"],
    "brack<e>ts.js"                     =>  ["brack<e>ts.js"                     , "brack-e-ts.js"         , "brack-e-ts.js"],
    "p|pes.js"                          =>  ["p|pes.js"                          , "p-pes.js"              , "p-pes.js"],
    "plus+.js"                          =>  ["plus+.js"                          , "plus.js"               , "plus.js"],
    "'five and six<seven'.js"           =>  ["'five and six<seven'.js"           , "five-and-six-seven.js" , "five-and-six-seven.js"],
    " space at front"                   =>  [" space at front"                   , "space-at-front"        , "space-at-front"],
    "space at end "                     =>  ["space at end "                     , "space-at-end"          , "space-at-end"],
    "relative/path/to/some/dir"         =>  ["relative/path/to/some/dir"         , "dir"                   , "relative" . DS . "path" . DS . "to" . DS . "some" . DS . "dir"],
    "/abs/path/to/some/dir"             =>  ["/abs/path/to/some/dir"             , "dir"                   , "" . DS . "abs" . DS . "path" . DS . "to" . DS . "some" . DS . "dir"],
    "~/.\u{0000}notssh/authorized_keys" =>  ["~/.\u{0000}notssh/authorized_keys" , "authorized-keys"       , "~" . DS . "." . DS . "authorized-keys"],
    ".period"                           =>  [".period"                           , ".period"               , ".period"],
    "period."                           =>  ["period."                           , "period"                , "period"],
    "h?w"                               =>  ["h?w"                               , "h-w"                   , "h-w"],
    "h/w"                               =>  ["h/w"                               , "w"                     , "h" . DS . "w"],
    "h*w"                               =>  ["h*w"                               , "h-w"                   , "h-w"],
    "./foobar"                          =>  ["./foobar"                          , "foobar"                , "foobar"],
    "../foobar"                         =>  ["../foobar"                         , "foobar"                , ".." . DS . "foobar"],
    "../../foobar"                      =>  ["../../foobar"                      , "foobar"                , ".." . DS . ".." . DS . "foobar"],
    "./././foobar"                      =>  ["./././foobar"                      , "foobar"                , "." . DS . "." . DS . "." . DS . "foobar"],
    "|*.what"                           =>  ["|*.what"                           , ".what"                 , ".what"],
    "LPT9.asdf"                         =>  ["LPT9.asdf"                         , ".asdf"                 , ".asdf"],
    "CON.asdf"                          =>  ["CON.asdf"                          , ".asdf"                 , ".asdf"],
    "COM5.asdf"                         =>  ["COM5.asdf"                         , ".asdf"                 , ".asdf"],
    "foobar..."                         =>  ["foobar..."                         , "foobar"                , "foobar"],
]);

test('default filename string', function (?string $filename, string $result): void {
    $output1 = FilenameSanitize::of($filename)
        ->defaultFilename('default-file-name.jpg')
        ->get();

    expect($output1)->toBe($result);
})->with([
    "if is using null"         =>  [null     , "default-file-name.jpg"],
    "if is using empty string" =>  [""       , "default-file-name.jpg"],
    "if is using prev char"    =>  [".."     , "default-file-name.jpg"],
    "if is using prev char 2"  =>  ["../"    , "default-file-name.jpg"],
    "if is using root char"    =>  ["."      , "default-file-name.jpg"],
    "if is using root char 2"  =>  ["./"     , "default-file-name.jpg"],
    "if is using next dir"     =>  ["/.."    , "default-file-name.jpg"],
    "if is using next dir"     =>  ["/../"   , "default-file-name.jpg"],
    "with asterix"             =>  ["*.|."   , "default-file-name.jpg"],
]);

test('throw exception if default filename missing', function (?string $filename): void {
    FilenameSanitize::of($filename)
        ->get();
})->with([
    "if is using null"         => null,
    "if is using empty string" => "",
    "if is using prev char"    => "..",
    "if is using prev char 2"  => "../",
    "if is using root char"    => ".",
    "if is using root char 2"  => "./",
    "if is using next dir"     => "/..",
    "if is using next dir"     => "/../",
    "with asterix"             => "*.|.",
])->throws(ValueError::class);
