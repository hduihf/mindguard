const express = require('express');
const cors = require('cors');
const path = require('path');
const fs = require('fs').promises;
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static('public'));

// In-memory storage (in production, use a proper database)
let userSessions = new Map();
let systemLogs = [];

// User Behavior Tracker Class
class BehaviorTracker {
    constructor(sessionId) {
        this.sessionId = sessionId;
        this.userBehavior = {
            harmfulDownloads: 0,
            ignoredWarnings: 0,
            totalDownloads: 0,
            alertLevel: 'safe',
            lastIgnoreTime: null,
            behaviorHistory: [],
            downloadTimes: [],
            patternFlags: {
                rapidDownloads: false,
                repeatedHarmful: false,
                timeBasedSuspicious: false
            },
            ipAddress: null,
            userAgent: null,
            sessionStartTime: Date.now(),
            riskScore: 0
        };
        
        this.thresholds = {
            warningLevel: 1,
            dangerLevel: 2,
            criticalLevel: 3,
            rapidDownloadTime: 30,
            maxRapidDownloads: 3
        };
    }

    updateSessionInfo(req) {
        this.userBehavior.ipAddress = req.ip || req.connection.remoteAddress;
        this.userBehavior.userAgent = req.get('User-Agent');
    }

    trackDownloadAttempt(fileName, fileType, wasBlocked = false) {
        const timestamp = Date.now();
        this.userBehavior.downloadTimes.push(timestamp);

        const logEntry = {
            timestamp,
            action: 'download_attempt',
            fileName,
            fileType,
            wasBlocked,
            sessionId: this.sessionId
        };

        this.userBehavior.behaviorHistory.push(logEntry);
        systemLogs.push(logEntry);

        if (!wasBlocked) {
            this.userBehavior.totalDownloads++;
            if (fileType === 'harmful') {
                this.userBehavior.harmfulDownloads++;
            }
        }

        this.analyzeDownloadPatterns();
        this.updateAlertLevel();
        this.updateRiskScore();
    }

    trackWarningIgnored(fileName) {
        const timestamp = Date.now();
        this.userBehavior.ignoredWarnings++;
        this.userBehavior.lastIgnoreTime = timestamp;

        const logEntry = {
            timestamp,
            action: 'warning_ignored',
            fileName,
            sessionId: this.sessionId
        };

        this.userBehavior.behaviorHistory.push(logEntry);
        systemLogs.push(logEntry);

        this.updateAlertLevel();
        this.updateRiskScore();
    }

    analyzeDownloadPatterns() {
        this.checkRapidDownloads();
        this.checkRepeatedHarmfulDownloads();
        this.checkTimeBasedPatterns();
    }

    checkRapidDownloads() {
        const now = Date.now();
        const recentDownloads = this.userBehavior.downloadTimes.filter(
            time => (now - time) < (this.thresholds.rapidDownloadTime * 1000)
        );

        if (recentDownloads.length >= this.thresholds.maxRapidDownloads) {
            this.userBehavior.patternFlags.rapidDownloads = true;
        }
    }

    checkRepeatedHarmfulDownloads() {
        if (this.userBehavior.harmfulDownloads >= 2) {
            this.userBehavior.patternFlags.repeatedHarmful = true;
        }
    }

    checkTimeBasedPatterns() {
        const now = Date.now();
        const sessionDuration = now - this.userBehavior.sessionStartTime;
        const hoursSinceStart = sessionDuration / (1000 * 60 * 60);

        // Flag suspicious behavior if too many harmful attempts in short time
        if (hoursSinceStart < 1 && this.userBehavior.harmfulDownloads >= 3) {
            this.userBehavior.patternFlags.timeBasedSuspicious = true;
        }
    }

    updateAlertLevel() {
        const { ignoredWarnings, patternFlags } = this.userBehavior;
        let newLevel = 'safe';

        if (ignoredWarnings >= this.thresholds.criticalLevel) {
            newLevel = 'critical';
        } else if (ignoredWarnings >= this.thresholds.dangerLevel) {
            newLevel = 'danger';
        } else if (ignoredWarnings >= this.thresholds.warningLevel) {
            newLevel = 'warning';
        }

        if (patternFlags.rapidDownloads || patternFlags.repeatedHarmful || patternFlags.timeBasedSuspicious) {
            const levels = ['safe', 'warning', 'danger', 'critical'];
            const currentIndex = levels.indexOf(newLevel);
            newLevel = levels[Math.min(currentIndex + 1, levels.length - 1)];
        }

        this.userBehavior.alertLevel = newLevel;
    }

    updateRiskScore() {
        const { harmfulDownloads, ignoredWarnings, totalDownloads, patternFlags } = this.userBehavior;
        
        let score = 0;
        score += harmfulDownloads * 20;
        score += ignoredWarnings * 15;
        
        if (patternFlags.rapidDownloads) score += 25;
        if (patternFlags.repeatedHarmful) score += 30;
        if (patternFlags.timeBasedSuspicious) score += 35;
        
        if (totalDownloads > 0) {
            const harmfulRatio = harmfulDownloads / totalDownloads;
            score += harmfulRatio * 50;
        }

        this.userBehavior.riskScore = Math.min(score, 100);
    }

    shouldBlockDownload(fileType) {
        if (fileType === 'safe') return false;
        
        const { alertLevel, ignoredWarnings, patternFlags, riskScore } = this.userBehavior;

        return alertLevel === 'critical' || 
               riskScore >= 80 || 
               (patternFlags.rapidDownloads && ignoredWarnings >= 2) ||
               patternFlags.timeBasedSuspicious;
    }

    getAlertConfiguration() {
        const { alertLevel, ignoredWarnings, harmfulDownloads } = this.userBehavior;
        const patterns = this.detectAdvancedPatterns();

        if (patterns.persistentAttacker) {
            return {
                level: 'red',
                icon: '🛡️',
                title: 'PERSISTENT THREAT DETECTED',
                message: `Multiple dangerous behavior patterns identified. ${ignoredWarnings} warnings ignored, ${harmfulDownloads} harmful downloads attempted.`,
                duration: 30000,
                canProceed: false,
                className: 'red-alert'
            };
        }

        const configs = {
            warning: {
                level: 'yellow',
                icon: '⚠️',
                title: 'Security Warning',
                message: 'This file has been flagged as potentially harmful. We recommend caution before downloading.',
                duration: 10000,
                canProceed: true,
                className: 'yellow-alert'
            },
            danger: {
                level: 'orange',
                icon: '🚨',
                title: 'High Risk Detected',
                message: `You previously ignored ${ignoredWarnings} security warning${ignoredWarnings > 1 ? 's' : ''}. This file poses a significant threat.`,
                duration: 20000,
                canProceed: true,
                className: 'orange-alert'
            },
            critical: {
                level: 'red',
                icon: '🛑',
                title: 'CRITICAL SECURITY THREAT',
                message: `${ignoredWarnings} security warnings ignored. Download blocked for system protection.`,
                duration: 30000,
                canProceed: false,
                className: 'red-alert'
            }
        };

        return configs[alertLevel] || configs.warning;
    }

    detectAdvancedPatterns() {
        const { ignoredWarnings, harmfulDownloads, patternFlags } = this.userBehavior;
        
        return {
            persistentAttacker: ignoredWarnings >= 3 && harmfulDownloads >= 2,
            escalatingThreat: harmfulDownloads >= 2,
            rapidBehavior: patternFlags.rapidDownloads,
            timeBasedThreat: patternFlags.timeBasedSuspicious
        };
    }

    getSessionData() {
        return {
            ...this.userBehavior,
            patterns: this.detectAdvancedPatterns(),
            sessionDuration: Date.now() - this.userBehavior.sessionStartTime
        };
    }

    reset() {
        this.userBehavior = {
            harmfulDownloads: 0,
            ignoredWarnings: 0,
            totalDownloads: 0,
            alertLevel: 'safe',
            lastIgnoreTime: null,
            behaviorHistory: [],
            downloadTimes: [],
            patternFlags: {
                rapidDownloads: false,
                repeatedHarmful: false,
                timeBasedSuspicious: false
            },
            ipAddress: this.userBehavior.ipAddress,
            userAgent: this.userBehavior.userAgent,
            sessionStartTime: Date.now(),
            riskScore: 0
        };
    }
}

// Utility functions
function generateSessionId() {
    return crypto.randomBytes(16).toString('hex');
}

function getOrCreateSession(req) {
    let sessionId = req.headers['x-session-id'] || generateSessionId();
    
    if (!userSessions.has(sessionId)) {
        const tracker = new BehaviorTracker(sessionId);
        tracker.updateSessionInfo(req);
        userSessions.set(sessionId, tracker);
    }
    
    return { sessionId, tracker: userSessions.get(sessionId) };
}

// API Routes

// Get session info and initialize
app.get('/api/session', (req, res) => {
    const { sessionId, tracker } = getOrCreateSession(req);
    
    res.json({
        sessionId,
        userBehavior: tracker.getSessionData(),
        serverTime: new Date().toISOString()
    });
});

// Handle download attempts
app.post('/api/download', (req, res) => {
    const { fileName, fileType } = req.body;
    const { sessionId, tracker } = getOrCreateSession(req);

    if (!fileName || !fileType) {
        return res.status(400).json({ error: 'Missing fileName or fileType' });
    }

    const isBlocked = tracker.shouldBlockDownload(fileType);
    
    if (isBlocked) {
        tracker.trackDownloadAttempt(fileName, fileType, true);
        return res.json({
            allowed: false,
            blocked: true,
            reason: 'Download blocked due to behavior patterns',
            userBehavior: tracker.getSessionData()
        });
    }

    if (fileType === 'harmful') {
        const alertConfig = tracker.getAlertConfiguration();
        return res.json({
            allowed: false,
            requiresConfirmation: true,
            alertConfig,
            userBehavior: tracker.getSessionData()
        });
    }

    // Safe file - allow immediately
    tracker.trackDownloadAttempt(fileName, fileType, false);
    res.json({
        allowed: true,
        userBehavior: tracker.getSessionData(),
        downloadUrl: `/downloads/${fileName}`
    });
});

// Handle warning confirmations
app.post('/api/confirm-download', (req, res) => {
    const { fileName, fileType, confirmed } = req.body;
    const { sessionId, tracker } = getOrCreateSession(req);

    if (confirmed) {
        tracker.trackWarningIgnored(fileName);
        tracker.trackDownloadAttempt(fileName, fileType, false);
        
        res.json({
            allowed: true,
            userBehavior: tracker.getSessionData(),
            downloadUrl: `/downloads/${fileName}`
        });
    } else {
        res.json({
            allowed: false,
            cancelled: true,
            userBehavior: tracker.getSessionData()
        });
    }
});

// Get current user behavior
app.get('/api/behavior/:sessionId?', (req, res) => {
    const sessionId = req.params.sessionId;
    
    if (sessionId && userSessions.has(sessionId)) {
        const tracker = userSessions.get(sessionId);
        res.json(tracker.getSessionData());
    } else {
        const { tracker } = getOrCreateSession(req);
        res.json(tracker.getSessionData());
    }
});

// Reset user behavior
app.post('/api/reset', (req, res) => {
    const { sessionId, tracker } = getOrCreateSession(req);
    tracker.reset();
    
    res.json({
        success: true,
        message: 'User behavior reset successfully',
        userBehavior: tracker.getSessionData()
    });
});

// Get system statistics
app.get('/api/stats', (req, res) => {
    const totalSessions = userSessions.size;
    const totalLogs = systemLogs.length;
    
    let totalDownloads = 0;
    let totalWarnings = 0;
    let activeCriticalUsers = 0;
    
    userSessions.forEach(tracker => {
        totalDownloads += tracker.userBehavior.totalDownloads;
        totalWarnings += tracker.userBehavior.ignoredWarnings;
        if (tracker.userBehavior.alertLevel === 'critical') {
            activeCriticalUsers++;
        }
    });

    res.json({
        totalSessions,
        totalDownloads,
        totalWarnings,
        activeCriticalUsers,
        totalLogs,
        serverUptime: process.uptime(),
        timestamp: new Date().toISOString()
    });
});

// Export behavior data
app.get('/api/export/:sessionId?', (req, res) => {
    const sessionId = req.params.sessionId;
    
    if (sessionId && userSessions.has(sessionId)) {
        const tracker = userSessions.get(sessionId);
        const data = {
            sessionId,
            exportTime: new Date().toISOString(),
            userData: tracker.getSessionData(),
            systemInfo: {
                serverUptime: process.uptime(),
                totalActiveSessions: userSessions.size
            }
        };
        
        res.setHeader('Content-Disposition', `attachment; filename="behavior_report_${sessionId}_${new Date().toISOString().split('T')[0]}.json"`);
        res.setHeader('Content-Type', 'application/json');
        res.json(data);
    } else {
        res.status(404).json({ error: 'Session not found' });
    }
});

// Simulate user behavior patterns
app.post('/api/simulate', (req, res) => {
    const { pattern } = req.body;
    const { sessionId, tracker } = getOrCreateSession(req);

    const simulations = {
        cautious: () => {
            tracker.trackDownloadAttempt('Document.pdf', 'safe');
            tracker.trackDownloadAttempt('presentation.pptx', 'safe');
        },
        risky: () => {
            tracker.trackDownloadAttempt('suspicious_file.exe', 'harmful');
            tracker.trackWarningIgnored('suspicious_file.exe');
        },
        rapid: () => {
            const files = [
                { name: 'Document.pdf', type: 'safe' },
                { name: 'suspicious_file.exe', type: 'harmful' },
                { name: 'malware_sample.zip', type: 'harmful' }
            ];
            
            files.forEach(file => {
                tracker.trackDownloadAttempt(file.name, file.type);
                if (file.type === 'harmful') {
                    tracker.trackWarningIgnored(file.name);
                }
            });
        },
        persistent: () => {
            const harmfulFiles = [
                'suspicious_file.exe', 'malware_sample.zip', 'trojan_horse.scr', 
                'keylogger.dll', 'backdoor.bat'
            ];
            
            harmfulFiles.forEach(fileName => {
                tracker.trackDownloadAttempt(fileName, 'harmful');
                tracker.trackWarningIgnored(fileName);
            });
        }
    };

    if (simulations[pattern]) {
        simulations[pattern]();
        res.json({
            success: true,
            message: `Simulated ${pattern} behavior pattern`,
            userBehavior: tracker.getSessionData()
        });
    } else {
        res.status(400).json({ error: 'Invalid simulation pattern' });
    }
});

// Admin routes for monitoring
app.get('/api/admin/sessions', (req, res) => {
    const sessions = [];
    userSessions.forEach((tracker, sessionId) => {
        sessions.push({
            sessionId,
            userBehavior: tracker.getSessionData(),
            lastActivity: Math.max(...tracker.userBehavior.downloadTimes, tracker.userBehavior.sessionStartTime)
        });
    });
    
    res.json(sessions);
});

app.get('/api/admin/logs', (req, res) => {
    const limit = parseInt(req.query.limit) || 100;
    const offset = parseInt(req.query.offset) || 0;
    
    const logs = systemLogs
        .slice(-limit - offset, systemLogs.length - offset)
        .reverse();
    
    res.json({
        logs,
        total: systemLogs.length,
        limit,
        offset
    });
});

// Serve static files and handle downloads
app.get('/downloads/:fileName', (req, res) => {
    const fileName = req.params.fileName;
    
    // Simulate file download
    res.setHeader('Content-Disposition', `attachment; filename="${fileName}"`);
    res.setHeader('Content-Type', 'application/octet-stream');
    
    // Send dummy file content
    const dummyContent = `This is a simulated download of ${fileName}\nTimestamp: ${new Date().toISOString()}\nFile size: ${Math.floor(Math.random() * 1000000)} bytes`;
    res.send(dummyContent);
});

// Error handling middleware
app.use((err, req, res, next) => {
    console.error('Server error:', err);
    res.status(500).json({ 
        error: 'Internal server error',
        message: err.message 
    });
});

// 404 handler
app.use((req, res) => {
    res.status(404).json({ error: 'Endpoint not found' });
});

// Cleanup old sessions periodically (every hour)
setInterval(() => {
    const now = Date.now();
    const maxAge = 24 * 60 * 60 * 1000; // 24 hours
    
    userSessions.forEach((tracker, sessionId) => {
        if (now - tracker.userBehavior.sessionStartTime > maxAge) {
            userSessions.delete(sessionId);
        }
    });
    
    // Keep only last 10000 system logs
    if (systemLogs.length > 10000) {
        systemLogs = systemLogs.slice(-5000);
    }
}, 60 * 60 * 1000);

// Start server
app.listen(PORT, () => {
    console.log(`🛡️  Dynamic Alert System Server running on port ${PORT}`);
    console.log(`📊 Admin interface: http://localhost:${PORT}/admin`);
    console.log(`🌐 API documentation: http://localhost:${PORT}/api/docs`);
});

module.exports = app;