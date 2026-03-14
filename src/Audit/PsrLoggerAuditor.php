<?php

declare(strict_types=1);

namespace Acme\SecurityKit\Audit;

use Psr\Log\LoggerInterface;
use Psr\Log\LogLevel;

/**
 * Auditor implementation that writes structured JSON context to a PSR-3 logger.
 */
final class PsrLoggerAuditor implements Auditor
{
    public function __construct(
        private readonly LoggerInterface $logger,
        private readonly string $channel = 'security',
    ) {}

    public function record(SecurityEvent $event): void
    {
        $level = match ($event->severity) {
            'critical' => LogLevel::CRITICAL,
            'error'    => LogLevel::ERROR,
            'warning'  => LogLevel::WARNING,
            'debug'    => LogLevel::DEBUG,
            default    => LogLevel::INFO,
        };

        $this->logger->log($level, "[{$this->channel}] {$event->type}", array_merge(
            $event->context,
            [
                'event_type' => $event->type,
                'occurred_at' => $event->at->format(\DateTimeInterface::ATOM),
                'channel'    => $this->channel,
            ]
        ));
    }
}
