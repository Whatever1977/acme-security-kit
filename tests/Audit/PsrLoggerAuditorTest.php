<?php
declare(strict_types=1);
namespace Acme\SecurityKit\Tests\Audit;

use Acme\SecurityKit\Audit\PsrLoggerAuditor;
use Acme\SecurityKit\Audit\SecurityEvent;
use PHPUnit\Framework\TestCase;
use Psr\Log\LoggerInterface;
use Psr\Log\LogLevel;

final class PsrLoggerAuditorTest extends TestCase
{
    public function testRecordsEventToLogger(): void
    {
        $logger  = new class implements LoggerInterface {
            public array $logs = [];
            public function log($level, \Stringable|string $message, array $context = []): void
            {
                $this->logs[] = compact('level', 'message', 'context');
            }
            public function emergency(\Stringable|string $m, array $c = []): void { $this->log(LogLevel::EMERGENCY, $m, $c); }
            public function alert(\Stringable|string $m, array $c = []): void { $this->log(LogLevel::ALERT, $m, $c); }
            public function critical(\Stringable|string $m, array $c = []): void { $this->log(LogLevel::CRITICAL, $m, $c); }
            public function error(\Stringable|string $m, array $c = []): void { $this->log(LogLevel::ERROR, $m, $c); }
            public function warning(\Stringable|string $m, array $c = []): void { $this->log(LogLevel::WARNING, $m, $c); }
            public function notice(\Stringable|string $m, array $c = []): void { $this->log(LogLevel::NOTICE, $m, $c); }
            public function info(\Stringable|string $m, array $c = []): void { $this->log(LogLevel::INFO, $m, $c); }
            public function debug(\Stringable|string $m, array $c = []): void { $this->log(LogLevel::DEBUG, $m, $c); }
        };

        $auditor = new PsrLoggerAuditor($logger);
        $event   = new SecurityEvent('jwt.invalid_signature', new \DateTimeImmutable(), ['kid' => 'abc'], 'warning');

        $auditor->record($event);

        self::assertCount(1, $logger->logs);
        self::assertSame(LogLevel::WARNING, $logger->logs[0]['level']);
        self::assertSame('jwt.invalid_signature', $logger->logs[0]['context']['event_type']);
    }
}
