<?php

declare(strict_types=1);

use OndrejVrto\FilenameSanitize\FilenameSanitize;

test('filename sanitize exception if is using root char', function (): void {
    (new FilenameSanitize())('.');
})->throws(Exception::class);

test('filename sanitize exception if is using prev char', function (): void {
    (new FilenameSanitize())('..');
})->throws(Exception::class);

test('filename sanitize exception if is using empty string', function (): void {
    (new FilenameSanitize())('');
})->throws(Exception::class);

test('input data conversion', function (mixed $input, string $result): void {
    $output = (new FilenameSanitize())($input);

    expect($output)->toBe($result);
})->with([
    'TODO'                           => ['TODO', 'todo'],
    '.github'                        => ['.github', '.github'],
    '.env.test'                      => ['.env.test', '.env.test'],
    '.hiddenFiles'                   => ['.hiddenFiles', '.hiddenfiles'],
    'File NaME.Zip'                  => ['File NaME.Zip',   'file-name.zip'],
    'file   name.zip'                => ['file   name.zip', 'file-name.zip'],
    'file___name.zip'                => ['file___name.zip', 'file-name.zip'],
    'file---name.zip'                => ['file---name.zip', 'file-name.zip'],
    'file...name..zip'               => ['file...name..zip', 'file.name.zip'],
    'file<->\\name/":.zip:'          => ['file<->\\name/":.zip:', 'file-name.zip'],
    '   file  name  .   zip'         => ['   file  name  .   zip', 'file-name.zip'],
    'file--.--.-.--name.zip'         => ['file--.--.-.--name.zip', 'file.name.zip'],
    'file-name|#\[\]&@()+,;=.zip'    => ['file-name|#\[\]&@()+,;=.zip', 'file-name.zip'],
    'js script'                      => ['<script>alert(1);</script>', 'script-alert-1-script'],
    'php function'                   => ['<?php malicious_function(); ?>`rm -rf /`', 'php-malicious-function-rm-rf'],
    'special char 0'                 => ['On / Off Again: My Journey to Stardom.jpg'.chr(0), 'on-off-again-my-journey-to-stardom.jpg'],
    'long filename to max 255 chars' => [
        '123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890.zip',
        '12345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901.zip'
    ],
]);
