<?php

declare(strict_types=1);

namespace Acme\SecurityKit\Tests\Audit;

use Acme\SecurityKit\Audit\NullAuditor;
use Acme\SecurityKit\Audit\PsrLoggerAuditor;
use Acme\SecurityKit\Audit\SecurityEvent;
use PHPUnit\Framework\TestCase;
use Psr\Log\LogLevel;
use Psr\Log\Test\TestLogger;

final class AuditTest extends TestCase
{
    // ─── SecurityEvent ───────────────────────────────────────────────

    public function testSecurityEventStoresAllFields(): void
    {
        $at    = new \DateTimeImmutable('2024-01-15T12:00:00Z');
        $event = new SecurityEvent(
            type: 'auth.login.failed',
            at: $at,
            context: ['ip' => '1.2.3.4', 'userId' => 'u-1'],
            severity: 'warning',
        );

        self::assertSame('auth.login.failed', $event->type);
        self::assertSame($at, $event->at);
        self::assertSame(['ip' => '1.2.3.4', 'userId' => 'u-1'], $event->context);
        self::assertSame('warning', $event->severity);
    }

    public function testSecurityEventDefaultSeverityIsInfo(): void
    {
        $event = new SecurityEvent('test.event', new \DateTimeImmutable());
        self::assertSame('info', $event->severity);
    }

    public function testSecurityEventDefaultContextIsEmpty(): void
    {
        $event = new SecurityEvent('test.event', new \DateTimeImmutable());
        self::assertSame([], $event->context);
    }

    // ─── NullAuditor ─────────────────────────────────────────────────

    public function testNullAuditorRecordsWithoutException(): void
    {
        $auditor = new NullAuditor();
        $auditor->record(new SecurityEvent('test', new \DateTimeImmutable()));
        // No exception = pass
        $this->expectNotToPerformAssertions();
    }

    public function testNullAuditorAcceptsAnySeverity(): void
    {
        $auditor = new NullAuditor();
        foreach (['info', 'warning', 'error', 'critical', 'debug', 'unknown'] as $severity) {
            $auditor->record(new SecurityEvent('test', new \DateTimeImmutable(), severity: $severity));
        }
        $this->expectNotToPerformAssertions();
    }

    // ─── PsrLoggerAuditor ────────────────────────────────────────────

    public function testPsrLoggerAuditorMapsInfoSeverity(): void
    {
        $logger  = new TestLogger();
        $auditor = new PsrLoggerAuditor($logger, 'security');

        $auditor->record(new SecurityEvent('test.info', new \DateTimeImmutable(), severity: 'info'));

        self::assertTrue($logger->hasInfoThatContains('[security] test.info'));
    }

    public function testPsrLoggerAuditorMapsWarningSeverity(): void
    {
        $logger  = new TestLogger();
        $auditor = new PsrLoggerAuditor($logger, 'security');

        $auditor->record(new SecurityEvent('csrf.invalid', new \DateTimeImmutable(), severity: 'warning'));

        self::assertTrue($logger->hasWarningThatContains('[security] csrf.invalid'));
    }

    public function testPsrLoggerAuditorMapsErrorSeverity(): void
    {
        $logger  = new TestLogger();
        $auditor = new PsrLoggerAuditor($logger, 'security');

        $auditor->record(new SecurityEvent('jwt.invalid', new \DateTimeImmutable(), severity: 'error'));

        self::assertTrue($logger->hasErrorThatContains('[security] jwt.invalid'));
    }

    public function testPsrLoggerAuditorMapsCriticalSeverity(): void
    {
        $logger  = new TestLogger();
        $auditor = new PsrLoggerAuditor($logger, 'security');

        $auditor->record(new SecurityEvent('oauth.reuse', new \DateTimeImmutable(), severity: 'critical'));

        self::assertTrue($logger->hasCriticalThatContains('[security] oauth.reuse'));
    }

    public function testPsrLoggerAuditorMapsUnknownSeverityToInfo(): void
    {
        $logger  = new TestLogger();
        $auditor = new PsrLoggerAuditor($logger, 'security');

        $auditor->record(new SecurityEvent('test', new \DateTimeImmutable(), severity: 'trace'));

        self::assertTrue($logger->hasInfoThatContains('test'));
    }

    public function testPsrLoggerAuditorIncludesContextInLogRecord(): void
    {
        $logger  = new TestLogger();
        $auditor = new PsrLoggerAuditor($logger, 'security');

        $auditor->record(new SecurityEvent(
            'auth.failed',
            new \DateTimeImmutable(),
            context: ['ip' => '127.0.0.1', 'userId' => 'u-42'],
            severity: 'warning',
        ));

        $records = $logger->records;
        self::assertNotEmpty($records);
        self::assertSame('127.0.0.1', $records[0]['context']['ip']);
        self::assertSame('u-42', $records[0]['context']['userId']);
    }

    public function testPsrLoggerAuditorIncludesEventTypeInContext(): void
    {
        $logger  = new TestLogger();
        $auditor = new PsrLoggerAuditor($logger, 'sec');

        $auditor->record(new SecurityEvent('jwt.expired', new \DateTimeImmutable(), severity: 'warning'));

        $records = $logger->records;
        self::assertSame('jwt.expired', $records[0]['context']['event_type']);
    }

    public function testPsrLoggerAuditorIncludesOccurredAtInContext(): void
    {
        $logger  = new TestLogger();
        $auditor = new PsrLoggerAuditor($logger, 'sec');
        $at      = new \DateTimeImmutable('2024-06-01T00:00:00+00:00');

        $auditor->record(new SecurityEvent('test', $at));

        $records = $logger->records;
        self::assertStringContainsString('2024-06-01', $records[0]['context']['occurred_at']);
    }

    public function testPsrLoggerAuditorUsesCustomChannel(): void
    {
        $logger  = new TestLogger();
        $auditor = new PsrLoggerAuditor($logger, 'my-channel');

        $auditor->record(new SecurityEvent('test', new \DateTimeImmutable()));

        $records = $logger->records;
        self::assertSame('my-channel', $records[0]['context']['channel']);
    }
}
