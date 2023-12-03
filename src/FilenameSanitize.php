<?php

declare(strict_types=1);

namespace OndrejVrto\FilenameSanitize;

use ValueError;

final class FilenameSanitize {
    private const SEPARATOR = '-';

    private readonly string $encoding;
    private readonly string $dirname;
    private readonly string $filename;
    private readonly string $extension;

    private ?string $prefix                 = null;
    private ?string $surffix                = null;
    private ?string $newExtension           = null;
    private ?string $defaultFilename        = null;
    private ?string $withBaseDirectory      = null;
    private bool    $withDirectory          = false;
    private bool    $addOldExtToName        = false;
    private bool    $addDirectoryToFilename = false;

    public static function of(?string $file): self {
        return (new self($file));
    }

    public function __construct(?string $file) {
        $file ??= '';

        $this->encoding = mb_detect_encoding($file) ?: 'ASCII';

        $path_parts = pathinfo($file);

        $this->dirname = ! array_key_exists('dirname', $path_parts) || '.' === $path_parts['dirname']
            ? ''
            : $this->sanitizeDirectory($path_parts['dirname']);

        $this->filename = $this->sanitizePartOfFilename($path_parts['filename']);

        $this->extension = array_key_exists('extension', $path_parts)
            ? $this->sanitizePartOfFilename($path_parts['extension'])
            : '';
    }


    /* -------------------------------------------------------------------------- */
    /*                              SETTINGS METHODS                              */
    /* -------------------------------------------------------------------------- */
    public function widthFilenamePrefix(string $prefix): self {
        $this->prefix = $this->sanitizePartOfFilename(
            $this->encodingString($prefix)
        );

        return $this;
    }

    public function widthFilenameSurffix(string $surffix): self {
        $this->surffix = $this->sanitizePartOfFilename(
            $this->encodingString($surffix)
        );

        return $this;
    }

    public function withNewExtension(string $extension): self {
        $this->newExtension = $this->sanitizePartOfFilename(
            $this->encodingString($extension)
        );

        return $this;
    }

    public function withBaseDirectory(string $baseDirectory): self {
        $this->withBaseDirectory = $this->sanitizeBaseDirectory(
            $this->encodingString($baseDirectory)
        );

        return $this;
    }

    public function defaultFilename(string $defaultFilename): self {
        $this->defaultFilename = $this->sanitizePartOfFilename(
            $this->encodingString($defaultFilename)
        );

        return $this;
    }

    public function moveActualExtensionToFilename(): self {
        $this->addOldExtToName = true;

        return $this;
    }

    public function addDirectoryToFilename(): self {
        $this->addDirectoryToFilename = true;

        return $this;
    }

    public function withDirectory(): self {
        $this->withDirectory = true;

        return $this;
    }

        /* -------------------------------------------------------------------------- */
    /*                                MAIN METHODS                                */
    /* -------------------------------------------------------------------------- */
    public function get(): string {
        // format:  /directory/sanitize-filenanme.ext
        $tmp = sprintf(
            '%s%s',
            $this->getDirectoryName(),
            $this->getformatedFilename($this->cutFilenameLength())
        );

        if (null === $this->withBaseDirectory) {
            return $tmp;
        }

        // format:  C:/base/dir/directory/sanitize-filenanme.ext
        $tmp = $this->withBaseDirectory.DIRECTORY_SEPARATOR.$tmp;

        // remove multiple separators
        return preg_replace([
            '/\\\{2,}/',
            '/\/{2,}/',
            '/\/\\\/',
            '#\\\/.*#',
        ], DIRECTORY_SEPARATOR, $tmp) ?? '';
    }


    /* -------------------------------------------------------------------------- */
    /*                           PRIVATE HELPERS METHODS                          */
    /* -------------------------------------------------------------------------- */
    private function encodingString(string $str): string {
        return mb_convert_encoding($str, $this->encoding) ?: $str;
    }

    private function sanitizePartOfFilename(string $filenamePart): string {
        if (empty($filenamePart)) {
            return '';
        }

        // Replace special characters
        $filenamePart = preg_replace([
            '/[<>:"\/\\\|?*]/',         // file system reserved https://en.wikipedia.org/wiki/Filename#Reserved_characters_and_words
            '/[\x00-\x1F]/',            // control characters http://msdn.microsoft.com/en-us/library/windows/desktop/aa365247%28v=vs.85%29.aspx
            '/[\x7F\xA0\xAD]/',         // non-printing characters DEL, NO-BREAK SPACE, SOFT HYPHEN
            '/[#\[\]@!$&\'()+,;=]/',    // URI reserved https://www.rfc-editor.org/rfc/rfc3986#section-2.2
            '/[{}^\~`]/',               // URL unsafe characters https://www.ietf.org/rfc/rfc1738.txt
            '/ +/',                     // reduce consecutive characters "file   name.zip" becomes "file-name.zip"
            '/_+/',                     // reduce consecutive characters "file___name.zip" becomes "file-name.zip"
            '/-+/',                     // reduce consecutive characters "file---name.zip" becomes "file-name.zip"
            '/^(con|prn|aux|nul|com[0-9]|lpt[0-9])$/i',     // Do not use the Windows reserved names. https://learn.microsoft.com/en-us/windows/win32/fileio/naming-a-file

        ], self::SEPARATOR, $filenamePart);

        if (empty($filenamePart)) {
            return '';
        }

        // reduce consecutive characters and replace with dot
        $filenamePart = preg_replace([
            '/-*\.-*/',     // "file--.--.-.--name.zip" becomes "file.name.zip"
            '/\.{2,}/',     // "file...name..zip" becomes "file.name.zip"
        ], '.', $filenamePart);

        if (empty($filenamePart)) {
            return '';
        }

        // clean start and end string with multiple trim pipe
        return trim(rtrim(rtrim(rtrim($filenamePart), '.'.self::SEPARATOR)), self::SEPARATOR);
    }

    private function sanitizeDirectory(string $dir): string {
        $tmp = preg_split("#\\\|\/#", $dir);

        if ( ! $tmp) {
            return '';
        }

        $tmp = array_map(
            fn (string $dirNode) => '.' === $dirNode || '..' === $dirNode || '~' === $dirNode
                ? $dirNode
                : $this->sanitizePartOfFilename($dirNode),
            $tmp
        );

        $tmp = array_filter($tmp, fn (string $dirNode) => ! empty($dirNode));

        if (preg_match("#^(\\\|\/).*#", $dir)) {
            array_unshift($tmp, null);
        }

        return implode(DIRECTORY_SEPARATOR, $tmp);
    }

    private function sanitizeBaseDirectory(string $dir): string {
        // replace separators
        return preg_replace(
            '/\/|\\\/',
            DIRECTORY_SEPARATOR,
            $dir
        ) ?? '';
    }

    private function getformatedFilename(string $filename): string {
        // Filename format:  prefix-directory-filename-surfix-oldExtension.newExtension
        $tmp = sprintf(
            '%s%s%s%s%s%s',
            null === $this->prefix ? '' : $this->prefix.self::SEPARATOR,
            $this->addDirectoryToFilename ? $this->getDirectoryForFilename() : '',
            $filename,
            null === $this->surffix ? '' : self::SEPARATOR.$this->surffix,
            $this->addOldExtToName && ! empty($this->extension) ? self::SEPARATOR.$this->extension : '',
            $this->getExtension(),
        );

        if (empty(trim($tmp))) {
            if (null === $this->defaultFilename) {
                throw new ValueError("Empty filename", 5);
            }

            $tmp = $this->defaultFilename;
        }

        // lowercase for windows/unix interoperability https://en.wikipedia.org/wiki/Filename
        return mb_strtolower($tmp, $this->encoding);
    }

    private function getExtension(): string {
        $tmpExt = $this->newExtension ?? $this->extension;

        return empty($tmpExt) ? "" : ".{$tmpExt}";
    }

    private function getDirectoryName(): string {
        return $this->withDirectory && '' !== $this->dirname
            ? $this->dirname.DIRECTORY_SEPARATOR
            : '';
    }

    private function getDirectoryForFilename(): string {
        return preg_replace(
            '/\\'.DIRECTORY_SEPARATOR.'/',
            self::SEPARATOR,
            $this->dirname.DIRECTORY_SEPARATOR
        ) ?? '';
    }

    private function cutFilenameLength(): string {
        // cut filename length to 255 bytes http://serverfault.com/a/9548/44086
        $fullLength = mb_strlen(
            $this->getformatedFilename($this->filename),
            $this->encoding
        );

        if ($fullLength <= 255) {
            return $this->filename;
        }

        $filenameLength =  mb_strlen(
            $this->filename,
            $this->encoding
        );

        $mustCutting = $fullLength - 255;

        return mb_strcut(
            string: $this->filename,
            start: 0,
            length: $filenameLength - $mustCutting,
            encoding: $this->encoding
        );
    }
}
