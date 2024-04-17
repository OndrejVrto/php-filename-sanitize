<?php

declare(strict_types=1);

namespace OndrejVrto\FilenameSanitize;

use ValueError;

class FilenameSanitize {
    private const DEFAULT_SEPARATOR = '-';

    private readonly string $encoding;
    private readonly string $originalDirname;
    private readonly string $originalFilename;
    private readonly string $originalExtension;

    private string  $filename  = '';
    private string  $separator = self::DEFAULT_SEPARATOR;

    private ?string $prefix                    = null;
    private ?string $suffix                    = null;
    private ?string $dirname                   = null;
    private ?string $extension                 = null;
    private ?string $newExtension              = null;
    private ?string $defaultFilename           = null;
    private ?string $withBaseDirectory         = null;
    private bool    $disableLowerCase          = false;
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

        $pathInfo = pathinfo($tmp);

        $this->encoding = mb_detect_encoding($tmp) ?: 'ASCII';

        $this->originalFilename = $pathInfo['filename'];

        $this->originalDirname = array_key_exists('dirname', $pathInfo) && '.' !== $pathInfo['dirname']
            ? $pathInfo['dirname']
            : '';

        $this->originalExtension = array_key_exists('extension', $pathInfo)
            ? $pathInfo['extension']
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

    public function customSeparator(string $separator): self {
        $this->separator = $this->sanitizeSeparator(
            $this->encodingString($separator)
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

    public function disableLowerCase(): self {
        $this->disableLowerCase = true;

        return $this;
    }


    /* -------------------------------------------------------------------------- */
    /*                                MAIN METHODS                                */
    /* -------------------------------------------------------------------------- */
    public function get(): string {
        $this->dirname = $this->sanitizeSubdirectory($this->originalDirname);

        $this->filename = $this->sanitizePartOfFilename($this->originalFilename);

        $this->extension = $this->sanitizePartOfFilename($this->originalExtension);

        // format:  /directory/sanitize-filenanme.ext
        $tmp = sprintf(
            '%s%s',
            $this->getSubdirectoryName(),
            $this->getformatedFilename($this->cutFilenameLength())
        );

        if (null !== $this->withBaseDirectory) {
            // format:  C:/base/dir/directory/sanitize-filenanme.ext
            $tmp = $this->withBaseDirectory . DIRECTORY_SEPARATOR . $tmp;
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
        if (empty($filenamePart) && '0' !== $filenamePart) {
            return '';
        }

        // Replace special characters
        $filenamePart = preg_replace([
            '/[<>:"\/\\\|?*]/',         // file system reserved https://en.wikipedia.org/wiki/Filename#Reserved_characters_and_words
            '/[\x00-\x1F\x7F\xA0]/u',   // non-printing characters DEL, NO-BREAK SPACE, SOFT HYPHEN https://stackoverflow.com/questions/1176904/how-to-remove-all-non-printable-characters-in-a-string
            '/[#\[\]@!$&\'()+,;=]/',    // URI reserved https://www.rfc-editor.org/rfc/rfc3986#section-2.2
            '/[{}^\~`]/',               // URL unsafe characters https://www.ietf.org/rfc/rfc1738.txt
            '/[ _-]+/',                 // reduce consecutive characters "file   name.zip", file___name.zip" or "file---name.zip" becomes "file-name.zip"
            '/^(con|prn|aux|nul|com[0-9]|lpt[0-9])$/i',     // Do not use the Windows reserved names. https://learn.microsoft.com/en-us/windows/win32/fileio/naming-a-file
        ], $this->separator, $filenamePart);

        if (empty($filenamePart) && '0' !== $filenamePart) {
            return '';
        }

        // reduce consecutive characters and replace with dot
        $filenamePart = preg_replace([
            '/-*\.-*/',     // "file--.--.-.--name.zip" becomes "file.name.zip"
            '/\.{2,}/',     // "file...name..zip" becomes "file.name.zip"
        ], '.', $filenamePart);

        if (empty($filenamePart) && '0' !== $filenamePart) {
            return '';
        }

        // clean start and end string
        $filenamePart = trim($filenamePart, " \n\r\t\v\0\{{$this->separator}}");

        // delete file extension separator at the end
        return rtrim($filenamePart, ".");
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
     * Sanitizes the custom separator.
     */
    private function sanitizeSeparator(string $separator): string {
        // remove special characters
        $separator = preg_replace([
            '/[{}^\~`]/',               // URL unsafe characters
            '/[<>:"\/\\\|?*]/',         // file system reserved characters
            '/[#\[\]@!$&\'()+,;=]/',    // URI reserved characters
            '/[\x00-\x1F\x7F\xA0]/u',   // non-printing characters
            '/\.+/',                    // dots
        ], '', $separator);

        // return set of allowed chars or default value
        return null === $separator || '' === $separator
            ? self::DEFAULT_SEPARATOR
            : $separator;
    }

    /**
     * Processes the new file name including prefixes, suffixes or other features
     */
    private function getformatedFilename(string $filename): string {
        // Filename format:  prefix-directory-filename-surfix-oldExtension.newExtension
        $tmp = sprintf(
            '%s%s%s%s%s%s',
            null === $this->prefix ? '' : $this->prefix . $this->separator,
            $this->addSubdirectoryToFilename ? $this->getSubdirectoryForFilename() : '',
            $filename,
            null === $this->suffix ? '' : $this->separator . $this->suffix,
            $this->addOldExtToName && ! empty($this->extension) ? $this->separator . $this->extension : '',
            $this->getExtension(),
        );

        $tmp = trim($tmp);

        // if filename is empty after sanitize, throw Exception or return default filename
        if (empty($tmp) && '0' !== $tmp) {
            if (null === $this->defaultFilename) {
                throw new ValueError('Empty filename', 5);
            }

            $tmp = $this->defaultFilename;
        }

        // lowercase for windows/unix interoperability https://en.wikipedia.org/wiki/Filename
        return $this->disableLowerCase
            ? $tmp
            : mb_strtolower($tmp, $this->encoding);
    }

    /**
     *  Returns the extension that was specified
     *  from the file name in the constructor of this class or a new extension.
     */
    private function getExtension(): string {
        $tmpExt = $this->newExtension ?? $this->extension;

        return empty($tmpExt) && '0' !== $tmpExt
            ? ''
            : ".{$tmpExt}";
    }

    /**
     *  Returns the value of the subdirectory that was specified
     *  from the file name in the constructor of this class.
     */
    private function getSubdirectoryName(): string {
        return $this->withSubdirectory && '' !== $this->dirname
            ? $this->dirname . DIRECTORY_SEPARATOR
            : '';
    }

    /**
     * Slugable directory - replaces all directory separators with commas
     */
    private function getSubdirectoryForFilename(): string {
        return str_replace(
            search:  DIRECTORY_SEPARATOR,
            replace: self::DEFAULT_SEPARATOR,
            subject: $this->dirname . DIRECTORY_SEPARATOR
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
