# NativePHP AES Encrypted Views Setup (Laravel)

This guide explains how to encrypt your Laravel Blade views, CSS, and JS files for use inside **NativePHP** Android apps using AES Encrypter.

---

## 📌 Folder Structure


1 Create a new secure directory inside your project:
```
app/Console/Commands/EncryptViews.php
```
add this here 
```
<?php

namespace App\Console\Commands;
use Illuminate\Console\Command;
use Illuminate\Support\Facades\File;

class EncryptViews extends Command
{
    protected $signature = 'views:encrypt';
    protected $description = 'Encrypt all Blade views (except errors) into storage/app/secure/views.enc';

    public function handle()
    {
        $viewsPath = resource_path('views');
        
        // $outDir   = storage_path('app/secure');
        $outDir = resource_path('secure');

        $outFile  = $outDir . DIRECTORY_SEPARATOR . 'views.enc';
        $password = env('VIEW_ENC_PASSWORD', null);

        if (!$password) {
            $this->error("Please set VIEW_ENC_PASSWORD in your .env before running this command.");
            return 1;
        }

        if (!File::exists($viewsPath)) {
            $this->error("Views folder not found: {$viewsPath}");
            return 1;
        }

        // Build a map: relative path => file content
        $map = [];
        $files = File::allFiles($viewsPath);

        foreach ($files as $file) {
            $real = $file->getRealPath();

            // Skip errors folder (we keep error views unencrypted)
            if (strpos($real, DIRECTORY_SEPARATOR . 'resources' . DIRECTORY_SEPARATOR . 'views' . DIRECTORY_SEPARATOR . 'errors') !== false) {
                continue;
            }

            $relative = ltrim(str_replace($viewsPath, '', $real), DIRECTORY_SEPARATOR);
            $map[$relative] = File::get($real);
        }

        if (empty($map)) {
            $this->info("No view files found to encrypt (except errors/). Nothing to do.");
            return 0;
        }

        // Prepare JSON blob of the map
        $json = json_encode($map, JSON_UNESCAPED_SLASHES);

        // Derive 32-byte key from password
        $key = hash('sha256', $password, true);

        $cipher = 'AES-256-CBC';
        $ivLen  = openssl_cipher_iv_length($cipher);
        $iv     = random_bytes($ivLen);

        // Use OPENSSL_RAW_DATA then base64 encode for storage
        $encryptedRaw = openssl_encrypt($json, $cipher, $key, OPENSSL_RAW_DATA, $iv);
        if ($encryptedRaw === false) {
            $this->error("Encryption failed (openssl_encrypt returned false).");
            return 1;
        }

        $payload = [
            'iv'   => base64_encode($iv),
            'data' => base64_encode($encryptedRaw),
        ];

        File::ensureDirectoryExists($outDir);
        File::put($outFile, base64_encode(json_encode($payload)));

        $this->info("Encrypted views saved to: {$outFile}");
        $this->info("Remember to remove original plain views from resources/views (except errors/) before packaging.");
        return 0;
    }
}

```
add this in .env file 
```
VIEW_ENC_PASSWORD=super_long_random_password_here_please_change
```


---

## 📌 How to Encrypt Your Views

Example encryption command 
after above code run this in cmd to create a view.enc in resources/secure/views.enc

```
php artisan views:encrypt
```


2 Create a new secure directory inside your project:

```
app/Services/ViewExtractor.php
```
place this code there 

```
<?php

namespace App\Services;

use Illuminate\Support\Facades\File;
use Illuminate\Support\Facades\Log;

class ViewExtractor
{
    public static function extract(): void
    {
        // Try candidate paths in order (resource first because debug showed it's present)
        $candidates = [
            resource_path('secure/views.enc'),
            base_path('native://bundle/resources/secure/views.enc'),
            base_path('app_storage/persisted_data/secure/views.enc'),
            storage_path('app/secure/views.enc'),
        ];

        $encFile = null;
        foreach ($candidates as $path) {
            if (File::exists($path) && is_readable($path)) {
                $encFile = $path;
                break;
            }
        }

        $viewsDir = resource_path('views');
        $password = env('VIEW_ENC_PASSWORD', null);

        if (!$password) {
            Log::warning("ViewExtractor: VIEW_ENC_PASSWORD is not set. Skipping extraction.");
            return;
        }

        self::ensureErrorViews();

        if ($encFile === null) {
            Log::error("ViewExtractor: Encrypted file NOT FOUND at any candidate path. Tried: " . implode(', ', $candidates));
            return;
        }

        Log::info("ViewExtractor: using encrypted file: {$encFile}");

        try {
            $b64 = File::get($encFile);
            $len = strlen($b64);
            Log::info("ViewExtractor: encrypted file size bytes: {$len}");

            if ($len === 0) {
                Log::error("ViewExtractor: encrypted file is empty.");
                return;
            }

            // Try base64 decode
            $payloadJson = base64_decode($b64, true);
            if ($payloadJson === false) {
                Log::error("ViewExtractor: base64_decode FAILED. First 120 chars: " . substr($b64, 0, 120));
                return;
            }

            $payload = @json_decode($payloadJson, true);
            if (!is_array($payload)) {
                Log::error("ViewExtractor: payload json decode FAILED. json_last_error=" . json_last_error() . " json_last_error_msg=" . json_last_error_msg());
                Log::debug("ViewExtractor: payload snippet: " . substr($payloadJson, 0, 500));
                return;
            }

            if (empty($payload['iv']) || empty($payload['data'])) {
                Log::error("ViewExtractor: payload missing 'iv' or 'data' keys.");
                return;
            }

            $iv = base64_decode($payload['iv'], true);
            $data = base64_decode($payload['data'], true);

            if ($iv === false || $data === false) {
                Log::error("ViewExtractor: base64_decode of iv or data failed.");
                return;
            }

            Log::info("ViewExtractor: iv length = " . strlen($iv) . " bytes; data length = " . strlen($data) . " bytes");

            if (strlen($iv) !== 16) {
                Log::error("ViewExtractor: IV length is not 16 bytes (required for AES-256-CBC).");
                return;
            }

            // Derive key (32 bytes)
            $key = hash('sha256', $password, true);

            // Decrypt
            $decryptedJson = @openssl_decrypt($data, 'AES-256-CBC', $key, OPENSSL_RAW_DATA, $iv);

            if ($decryptedJson === false || $decryptedJson === null) {
                Log::error("ViewExtractor: openssl_decrypt returned false/null. OpenSSL errors:");
                while ($err = openssl_error_string()) {
                    Log::error("openssl: " . $err);
                }
                return;
            }

            $map = @json_decode($decryptedJson, true);
            if (!is_array($map)) {
                Log::error("ViewExtractor: decrypted JSON map invalid. json_last_error=" . json_last_error() . " msg=" . json_last_error_msg());
                Log::debug("ViewExtractor: decrypted snippet: " . substr($decryptedJson, 0, 500));
                return;
            }

            // create views dir if missing
            if (!File::exists($viewsDir)) {
                File::makeDirectory($viewsDir, 0777, true);
            }

            $count = 0;
            foreach ($map as $relative => $content) {
                // sanitize relative path
                $relative = ltrim(str_replace(['..', './', '\\'], ['', '', '/'], $relative), '/');
                $dest = $viewsDir . DIRECTORY_SEPARATOR . $relative;
                $dir  = dirname($dest);
                if (!File::exists($dir)) File::makeDirectory($dir, 0777, true);
                File::put($dest, $content);
                $count++;
            }

            Log::info("ViewExtractor: decrypted and restored {$count} view files.");

            // schedule cleanup after request
            register_shutdown_function(function () use ($viewsDir) {
                self::cleanup($viewsDir);
            });

        } catch (\Throwable $e) {
            Log::error("ViewExtractor: exception while extracting views: " . $e->getMessage());
            Log::debug($e->getTraceAsString());
        }
    }

    private static function ensureErrorViews(): void
    {
        $src = base_path('resources/views/errors');
        $dst = resource_path('views/errors');

        if (!File::exists($dst) && File::exists($src)) {
            File::copyDirectory($src, $dst);
            Log::info("ViewExtractor: copied default error views.");
        }
    }

    private static function cleanup(string $viewsDir): void
    {
        try {
            foreach (scandir($viewsDir) as $item) {
                if (in_array($item, ['.', '..', 'errors'], true)) continue;
                $path = $viewsDir . DIRECTORY_SEPARATOR . $item;
                if (is_dir($path)) {
                    File::deleteDirectory($path);
                } else {
                    @unlink($path);
                }
            }
        } catch (\Throwable $e) {
            Log::warning("ViewExtractor cleanup warning: " . $e->getMessage());
        }
    }
}
```


---

## 📌 Service Provider Setup

In **AppServiceProvider.php**, place this inside the `register()`  or `boot()` method in app/Provider/AppServiceProvider.php:
add this there

```
ViewExtractor::extract();
```


---

## 📌 NativePHP Packaging

No extra settings needed!

Just build your app:

```
php artisan native:run
```

Your encrypted Blade files will work perfectly inside the APK.

---

## 📌 Important Notes

- Keep your encryption key safe.
- Never upload unencrypted `.blade.php` files to GitHub.
- You can encrypt CSS/JS too using the same method.
- Android sometimes fails if the encrypted folder is misplaced — keep it exactly as:

```
resources/secure/views.enc
```

---

## ✔ Success

If everything is set correctly, your Android app will render encrypted views with **no 500 error**, just like your test case.

---

## Author

**Engrayken**
