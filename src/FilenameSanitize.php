<?php

declare(strict_types=1);

namespace OndrejVrto\FilenameSanitize;

use ValueError;

class FilenameSanitize {
    private const SEPARATOR = '-';

    private readonly string $encoding;
    private readonly string $dirname;
    private readonly string $filename;
    private readonly string $extension;

    private ?string $prefix                    = null;
    private ?string $suffix                    = null;
    private ?string $newExtension              = null;
    private ?string $defaultFilename           = null;
    private ?string $withBaseDirectory         = null;
    private bool    $withSubdirectory          = false;
    private bool    $addOldExtToName           = false;
    private bool    $addSubdirectoryToFilename = false;

    // handle static instance of this class
    public static function of(?string $file): self {
        return (new self($file));
    }

    public function __construct(?string $file) {
        $tmp = null !== $file
            ? $this->changeBackSlashes($file)
            : '';

        $this->encoding = mb_detect_encoding($tmp) ?: 'ASCII';

        $path_parts = pathinfo($tmp);

        $this->filename = $this->sanitizePartOfFilename($path_parts['filename']);

        $this->dirname = array_key_exists('dirname', $path_parts) && '.' !== $path_parts['dirname']
            ? $this->sanitizeSubdirectory($path_parts['dirname'])
            : '';

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

    public function widthFilenameSuffix(string $suffix): self {
        $this->suffix = $this->sanitizePartOfFilename(
            $this->encodingString($suffix)
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
        $this->withBaseDirectory = $this->changeBackSlashes(
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

    public function addActualExtensionToFilename(): self {
        $this->addOldExtToName = true;

        return $this;
    }

    public function addSubdirectoryToFilename(): self {
        $this->addSubdirectoryToFilename = true;

        return $this;
    }

    public function withSubdirectory(): self {
        $this->withSubdirectory = true;

        return $this;
    }

    /* -------------------------------------------------------------------------- */
    /*                                MAIN METHODS                                */
    /* -------------------------------------------------------------------------- */
    public function get(): string {
        // format:  /directory/sanitize-filenanme.ext
        $tmp = sprintf(
            '%s%s',
            $this->getSubdirectoryName(),
            $this->getformatedFilename($this->cutFilenameLength())
        );

        if (null !== $this->withBaseDirectory) {
            // format:  C:/base/dir/directory/sanitize-filenanme.ext
            $tmp = $this->withBaseDirectory.DIRECTORY_SEPARATOR.$tmp;
        }

        // remove multiple separators
        return preg_replace(
            ['/\\\{2,}/', '/\/{2,}/'],
            DIRECTORY_SEPARATOR,
            $tmp
        ) ?? '';
    }


    /* -------------------------------------------------------------------------- */
    /*                           PRIVATE HELPERS METHODS                          */
    /* -------------------------------------------------------------------------- */

    /**
     * Change all delimiters to default according to the operating system you are using
     *   in Windows => "\"
     *   in UNIX    => "/"
     */
    private function changeBackSlashes(string $dir): string {
        return preg_replace(
            '/\/|\\\/',
            DIRECTORY_SEPARATOR,
            $dir
        ) ?? '';
    }

    /**
     * We convert all used strings into the source format
     */
    private function encodingString(string $str): string {
        return mb_convert_encoding($str, $this->encoding) ?: $str;
    }

    /**
     * Sanitizes the file name.
     */
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

    /**
     * Cleans individual parts of the directory
     */
    private function sanitizeSubdirectory(string $dir): string {
        $explodedDir = explode(DIRECTORY_SEPARATOR, $dir);

        if ( ! is_array($explodedDir)) {
            return '';
        }

        // sanitize directory nodes except for three special cases
        $tmp = array_map(
            fn (string $dirNode) => '.' === $dirNode || '..' === $dirNode || '~' === $dirNode
                ? $dirNode
                : $this->sanitizePartOfFilename($dirNode),
            $explodedDir
        );

        // join directory nodes to path
        return implode(DIRECTORY_SEPARATOR, $tmp);
    }

    /**
     * Processes the new file name including prefixes, suffixes or other features
     */
    private function getformatedFilename(string $filename): string {
        // Filename format:  prefix-directory-filename-surfix-oldExtension.newExtension
        $tmp = sprintf(
            '%s%s%s%s%s%s',
            null === $this->prefix ? '' : $this->prefix.self::SEPARATOR,
            $this->addSubdirectoryToFilename ? $this->getSubdirectoryForFilename() : '',
            $filename,
            null === $this->suffix ? '' : self::SEPARATOR.$this->suffix,
            $this->addOldExtToName && ! empty($this->extension) ? self::SEPARATOR.$this->extension : '',
            $this->getExtension(),
        );

        // if filename is empty after sanitize, throw Exception or return default filename
        if (empty(trim($tmp))) {
            if (null === $this->defaultFilename) {
                throw new ValueError('Empty filename', 5);
            }

            $tmp = $this->defaultFilename;
        }

        // lowercase for windows/unix interoperability https://en.wikipedia.org/wiki/Filename
        return mb_strtolower($tmp, $this->encoding);
    }

    /**
     *  Returns the extension that was specified
     *  from the file name in the constructor of this class or a new extension.
     */
    private function getExtension(): string {
        $tmpExt = $this->newExtension ?? $this->extension;

        return empty($tmpExt) ? '' : ".{$tmpExt}";
    }

    /**
     *  Returns the value of the subdirectory that was specified
     *  from the file name in the constructor of this class.
     */
    private function getSubdirectoryName(): string {
        return $this->withSubdirectory && '' !== $this->dirname
            ? $this->dirname.DIRECTORY_SEPARATOR
            : '';
    }

    /**
     * Slugable directory - replaces all separators with commas
     */
    private function getSubdirectoryForFilename(): string {
        return str_replace(
            search:  DIRECTORY_SEPARATOR,
            replace: self::SEPARATOR,
            subject: $this->dirname.DIRECTORY_SEPARATOR
        );
    }

    /**
     * Cut filename length to 255 bytes http://serverfault.com/a/9548/44086
     * is used multibyte operations
     */
    private function cutFilenameLength(): string {
        // the base length of the fully qualified file name
        $fullLength = mb_strlen(
            $this->getformatedFilename($this->filename),
            $this->encoding
        );

        // if the length is shorter than 255 characters, everything is OK
        if ($fullLength <= 255) {
            return $this->filename;
        }

        // calculates the required number of characters for truncation
        $filenameLength = mb_strlen(
            $this->filename,
            $this->encoding
        );

        $mustCutting = $fullLength - 255;

        // shortens only of the file name by the required number of characters
        // prefix, suffix and other additional information will not be shortened
        return mb_strcut(
            string:   $this->filename,
            start:    0,
            length:   $filenameLength - $mustCutting,
            encoding: $this->encoding
        );
    }
}
