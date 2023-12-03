<?php

declare(strict_types=1);

use OndrejVrto\FilenameSanitize\FilenameSanitize;

test('throw exception', function (string $input): void {
    (new FilenameSanitize($input))->get();
})
    ->throws(\ValueError::class)
    ->with([
        'if is using empty string' => '',
        'if is using prev char'    => '..',
        'if is using root char'    => '.',
    ]);

test('filename', function (string $input, string $result): void {
    $output = (new FilenameSanitize($input))->get();

    expect($output)->toBe($result);

    // short static format
    $output2 = FilenameSanitize::of($input)->get();

    expect($output2)->toBe($result);
})->with([
    'Basic'                           => ['file-name.ext'             , 'file-name.ext'],
    'Multibyte characters'            => ['火|车..票'                  , '火-车.票'],
    'Only Extencion'                  => ['.github'                   , '.github'],
    'Only name'                       => ['filename'                  , 'filename'],
    'Multi Extension'                 => ['.env.test'                 , '.env.test'],
    'Upper case'                      => ['File NaME.Zip'             , 'file-name.zip'],
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

    'php function' => [
        '<?php malicious_function(); ?>`rm -rf `',
        'php-malicious-function-rm-rf'
    ],
    'special char 0' => [
        'On | Off Again: My Journey to Stardom.jpg'.chr(0),
        'on-off-again-my-journey-to-stardom.jpg'
    ],
    'long filename to max 255 chars' => [
        '123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890.zip',
        '12345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901.zip'
    ],
]);

test('directory', function (string $input, string $result1, string $result2): void {
    $output1 = (new FilenameSanitize($input))
        ->withDirectory()
        ->get();

    expect($output1)->toBe($result1);

    $output2 = FilenameSanitize::of($input)
        ->get();

    expect($output2)->toBe($result2);
})->with([
    'Basic'                           => ['\dir\dir\file-name.ext'        , '\dir\dir\file-name.ext'       , 'file-name.ext'],
    'Windows'                         => ['C:\dir\dir\file-name.ext'      , 'C\dir\dir\file-name.ext'     , 'file-name.ext'],
    'Multibyte characters'            => ['火/车~车..票'                   , '火\车-车.票'                    , '车-车.票'],
    'Only Extencion'                  => ['/dir\dir/.github'              , '\dir\dir\.github'             , '.github'],
    'Only name'                       => ['/dir\dir/filename'             , '\dir\dir\filename'            , 'filename'],
    'Multi Extension'                 => ['/dir\dir/.env.test'            , '\dir\dir\.env.test'           , '.env.test'],
    'URL unsafe characters'           => ['~dir/-{d}i^r/filename.[zip]'   , 'dir\d-i-r\filename.zip'       , 'filename.zip'],
    'URI reserved characters'         => ['dir\|#[\file]&n@a(m)e+,;=.zip' , 'dir\file-n-a-m-e.zip'         , 'file-n-a-m-e.zip'],
    'relative path'                   => ['./..\dir/file-name.zip'        , '.\..\dir\file-name.zip'       , 'file-name.zip'],
    'relative path 2'                 => ['~/../..\dir/../file-name.zip'  , '~\..\..\dir\..\file-name.zip' , 'file-name.zip'],
]);

test('prefix and suffix', function (string $input, string $result1, string $result2): void {
    $output1 = (new FilenameSanitize($input))
        ->withDirectory()
        ->widthFilenamePrefix('prefix')
        ->widthFilenameSurfix('suffix')
        ->get();

    expect($output1)->toBe($result1);

    $output2 = FilenameSanitize::of($input)
        ->widthFilenamePrefix('prefix')
        ->widthFilenameSurfix('suffix')
        ->get();

    expect($output2)->toBe($result2);
})->with([
    'Basic'                           => ['\dir\dir\file-name.ext'       , '\dir\dir\prefix-file-name-suffix.ext'   , 'prefix-file-name-suffix.ext'],
    'Windows'                         => ['C:\dir\dir\file-name.ext'     , 'C\dir\dir\prefix-file-name-suffix.ext' , 'prefix-file-name-suffix.ext'],
    'Multibyte characters'            => ['火/车~车..票'                  , '火\prefix-车-车-suffix.票'                , 'prefix-车-车-suffix.票'],
    'Only Extencion'                  => ['/dir\dir/.github'             , '\dir\dir\prefix--suffix.github'         , 'prefix--suffix.github'],
    'Only name'                       => ['/dir\dir/filename'            , '\dir\dir\prefix-filename-suffix'        , 'prefix-filename-suffix'],
    'Multi Extension'                 => ['/dir\dir/.env.test'           , '\dir\dir\prefix-.env-suffix.test'       , 'prefix-.env-suffix.test'],
    'URL unsafe characters'           => ['~dir/-{d}i^r/filename.[zip]'  , 'dir\d-i-r\prefix-filename-suffix.zip'   , 'prefix-filename-suffix.zip'],
    'URI reserved characters'         => ['dir\|#[\file]&n@a(m)e+,;=.zip', 'dir\prefix-file-n-a-m-e-suffix.zip'     , 'prefix-file-n-a-m-e-suffix.zip'],
]);

test('extension', function (string $input, string $result1, string $result2, string $result3, string $result4): void {
    $output1 = (new FilenameSanitize($input))
        ->withNewExtension('webp')
        ->get();

    expect($output1)->toBe($result1);

    $output2 = FilenameSanitize::of($input)
        ->moveActualExtensionToFilename()
        ->get();

    expect($output2)->toBe($result2);

    $output3 = (new FilenameSanitize($input))
        ->moveActualExtensionToFilename()
        ->withNewExtension('webp')
        ->get();

    expect($output3)->toBe($result3);

    $output4 = FilenameSanitize::of($input)
        ->moveActualExtensionToFilename()
        ->widthFilenameSurfix('suffix')
        ->withNewExtension('webp')
        ->get();

    expect($output4)->toBe($result4);
})->with([
    'Basic'                           => ['\dir\dir\file-name.ext'       , 'file-name.webp'   , 'file-name-ext.ext'   , 'file-name-ext.webp'   , 'file-name-suffix-ext.webp'],
    'Multibyte characters'            => ['火/车~车..票'                  , '车-车.webp'        , '车-车-票.票'           , '车-车-票.webp'         , '车-车-suffix-票.webp'],
    'Only Extencion'                  => ['/dir\dir/.github'             , '.webp'            , '-github.github'      , '-github.webp'         , '-suffix-github.webp'],
    'Only name'                       => ['/dir\dir/filename'            , 'filename.webp'    , 'filename'            , 'filename.webp'        , 'filename-suffix.webp'],
    'Multi Extension'                 => ['/dir\dir/.env.test'           , '.env.webp'        , '.env-test.test'      , '.env-test.webp'       , '.env-suffix-test.webp'],
    'URL unsafe characters'           => ['~dir/-{d}i^r/filename.[zip]'  , 'filename.webp'    , 'filename-zip.zip'    , 'filename-zip.webp'    , 'filename-suffix-zip.webp'],
    'URI reserved characters'         => ['dir\|#[\file]&n@a(m)e+,;=.zip', 'file-n-a-m-e.webp', 'file-n-a-m-e-zip.zip', 'file-n-a-m-e-zip.webp', 'file-n-a-m-e-suffix-zip.webp'],
]);


test('base directory', function (string $baseDirectory, string $filename, string $result): void {
    $output = (new FilenameSanitize($filename))
        ->withBaseDirectory($baseDirectory)
        ->withDirectory()
        ->get();

    expect($output)->toBe($result);
})->with([
    'Basic'                  => ['C:/foo/bar'   , '\..\dir\file-name.zip'  , 'C:/foo/bar\..\dir\file-name.zip'],
    'Without separator'      => ['C:/foo/bar'   , '..\dir\file-name.zip'   , 'C:/foo/bar\..\dir\file-name.zip'],
    'Multiple separator 1'   => ['C:/foo/bar/'  , '\..\dir\file-name.zip'  , 'C:/foo/bar\..\dir\file-name.zip'],
    'Multiple separator 2'   => ['C:/foo/bar/'  , '/..\dir\file-name.zip'  , 'C:/foo/bar\..\dir\file-name.zip'],
    'Multiple separator 3'   => ['C:/foo/bar\\' , '\..\dir\file-name.zip'  , 'C:/foo/bar\..\dir\file-name.zip'],
    'Multiple separator 4'   => ['C:/foo/bar\\' , '\..\dir\file-name.zip'  , 'C:/foo/bar\..\dir\file-name.zip'],
    'Unix root'              => ['\tmp\foo\\'     , 'bar\file-name.zip'     , '\tmp\foo\bar\file-name.zip'],
]);

test('directory to filename', function (): void {
    $output = FilenameSanitize::of('C:/foo/bar/file-name.zip')
        ->addDirectoryToFilename()
        ->get();
    expect($output)->toBe('c-foo-bar-file-name.zip');

    $output = FilenameSanitize::of('foo/bar/file-name.zip')
        ->addDirectoryToFilename()
        ->withDirectory()
        ->get();
    expect($output)->toBe('foo\bar\foo-bar-file-name.zip');

    $output = FilenameSanitize::of('foo/bar/file-name.zip')
        ->moveActualExtensionToFilename()
        ->widthFilenamePrefix('prefix')
        ->widthFilenameSurfix('surfix')
        ->withBaseDirectory('C:\baz')
        ->addDirectoryToFilename()
        ->withNewExtension('webp')
        ->withDirectory()
        ->get();

    expect($output)->toBe('C:\baz\foo\bar\prefix-foo-bar-file-name-surfix-zip.webp');

    $output = FilenameSanitize::of('\foo2\bar2\baz2\long-file-name-12345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890.zip')
        ->widthFilenamePrefix('looong-prefix')
        ->widthFilenameSurfix('looong-surfix')
        ->withBaseDirectory('C:\foo\bar\baz')
        ->moveActualExtensionToFilename()
        ->withNewExtension('webp')
        ->addDirectoryToFilename()
        ->withDirectory()
        ->get();

    expect($output)->toBe('C:\foo\bar\baz\foo2\bar2\baz2\looong-prefix--foo2-bar2-baz2-long-file-name-1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567-looong-surfix-zip.webp');
});

test('test from another package', function (string $filename, string $result1, string $result2): void {
    $output1 = FilenameSanitize::of($filename)
        ->get();

    expect($output1)->toBe($result1);

    $output2 = FilenameSanitize::of($filename)
        ->withDirectory()
        ->get();

    expect($output2)->toBe($result2);
})->with([
    "résumé"                            =>  ["résumé"                            , "résumé"                , "résumé"],
    "hello\u{0000}world"                =>  ["hello\u{0000}world"                , "hello-world"           , "hello-world"],
    "hello [enter] world"               =>  ["hello\nworld"                      , "hello-world"           , "hello-world"],
    "semi;colon.js"                     =>  ["semi;colon.js"                     , "semi-colon.js"         , "semi-colon.js"],
    ";leading-semi.js"                  =>  [";leading-semi.js"                  , "leading-semi.js"       , "leading-semi.js"],
    "slash\\.js"                        =>  ["slash\\.js"                        , ".js"                   , "slash\.js"],
    "slash/.js"                         =>  ["slash/.js"                         , ".js"                   , "slash\.js"],
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
    "relative/path/to/some/dir"         =>  ["relative/path/to/some/dir"         , "dir"                   , "relative\path\\to\some\dir"],
    "/abs/path/to/some/dir"             =>  ["/abs/path/to/some/dir"             , "dir"                   , "\abs\path\\to\some\dir"],
    "~/.\u{0000}notssh/authorized_keys" =>  ["~/.\u{0000}notssh/authorized_keys" , "authorized-keys"       , "~\.\authorized-keys"],
    ".period"                           =>  [".period"                           , ".period"               , ".period"],
    "period."                           =>  ["period."                           , "period"                , "period"],
    "h?w"                               =>  ["h?w"                               , "h-w"                   , "h-w"],
    "h/w"                               =>  ["h/w"                               , "w"                     , "h\w"],
    "h*w"                               =>  ["h*w"                               , "h-w"                   , "h-w"],
    "./"                                =>  ["./"                                , ""                      , ""],
    "../"                               =>  ["../"                               , ""                      , ""],
    "/.."                               =>  ["/.."                               , ""                      , ""],
    "/../"                              =>  ["/../"                              , ""                      , ""],
    "*.|."                              =>  ["*.|."                              , ""                      , ""],
    "./"                                =>  ["./"                                , ""                      , ""],
    "./foobar"                          =>  ["./foobar"                          , "foobar"                , "foobar"],
    "../foobar"                         =>  ["../foobar"                         , "foobar"                , "..\\foobar"],
    "../../foobar"                      =>  ["../../foobar"                      , "foobar"                , "..\..\\foobar"],
    "./././foobar"                      =>  ["./././foobar"                      , "foobar"                , ".\.\.\\foobar"],
    "|*.what"                           =>  ["|*.what"                           , ".what"                 , ".what"],
    "LPT9.asdf"                         =>  ["LPT9.asdf"                         , ".asdf"                 , ".asdf"],
    "CON.asdf"                          =>  ["CON.asdf"                          , ".asdf"                 , ".asdf"],
    "COM5.asdf"                         =>  ["COM5.asdf"                         , ".asdf"                 , ".asdf"],
    "foobar..."                         =>  ["foobar..."                         , "foobar"                , "foobar"],
]);
