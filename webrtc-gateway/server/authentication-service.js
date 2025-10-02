/**
 * Authentication Service - Handles user authentication and session management
 */

const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const fs = require('fs');
const path = require('path');

class AuthenticationService {
    constructor(config) {
        this.config = config;
        this.users = new Map();
        this.sessions = new Map();
        this.jwtSecret = config.secret;
        this.tokenExpiry = config.tokenExpiry || '24h';
        
        this.initializeUsers();
    }
    
    initializeUsers() {
        // Load users from file or create default users
        const usersFile = path.join(__dirname, '../data/users.json');
        
        try {
            if (fs.existsSync(usersFile)) {
                const usersData = JSON.parse(fs.readFileSync(usersFile, 'utf8'));
                for (const user of usersData) {
                    this.users.set(user.username, user);
                }
                console.log(`Loaded ${this.users.size} users from file`);
            } else {
                // Create default admin user
                this.createDefaultUsers();
            }
        } catch (error) {
            console.error('Error loading users:', error);
            this.createDefaultUsers();
        }
    }
    
    createDefaultUsers() {
        // Create default admin user
        const adminUser = {
            id: 'admin',
            username: 'admin',
            email: 'admin@fgcom-mumble.local',
            password: this.hashPassword('admin123'),
            role: 'admin',
            createdAt: new Date().toISOString(),
            lastLogin: null
        };
        
        this.users.set('admin', adminUser);
        console.log('Created default admin user (username: admin, password: admin123)');
    }
    
    async authenticate(username, password) {
        try {
            console.log(`Authenticating user: ${username}`);
            
            const user = this.users.get(username);
            if (!user) {
                return {
                    success: false,
                    message: 'Invalid username or password'
                };
            }
            
            const passwordMatch = await bcrypt.compare(password, user.password);
            if (!passwordMatch) {
                return {
                    success: false,
                    message: 'Invalid username or password'
                };
            }
            
            // Update last login
            user.lastLogin = new Date().toISOString();
            
            // Generate JWT token
            const token = jwt.sign(
                { 
                    userId: user.id, 
                    username: user.username, 
                    role: user.role 
                },
                this.jwtSecret,
                { expiresIn: this.tokenExpiry }
            );
            
            // Create session
            const sessionId = this.generateSessionId();
            this.sessions.set(sessionId, {
                userId: user.id,
                username: user.username,
                role: user.role,
                createdAt: new Date(),
                lastActivity: new Date()
            });
            
            console.log(`User ${username} authenticated successfully`);
            
            return {
                success: true,
                token,
                sessionId,
                user: {
                    id: user.id,
                    username: user.username,
                    email: user.email,
                    role: user.role,
                    lastLogin: user.lastLogin
                }
            };
            
        } catch (error) {
            console.error('Authentication error:', error);
            return {
                success: false,
                message: 'Authentication failed'
            };
        }
    }
    
    async register(username, password, email) {
        try {
            console.log(`Registering new user: ${username}`);
            
            // Check if user already exists
            if (this.users.has(username)) {
                return {
                    success: false,
                    message: 'Username already exists'
                };
            }
            
            // Validate input
            if (!username || username.length < 3) {
                return {
                    success: false,
                    message: 'Username must be at least 3 characters long'
                };
            }
            
            if (!password || password.length < 6) {
                return {
                    success: false,
                    message: 'Password must be at least 6 characters long'
                };
            }
            
            if (!email || !this.isValidEmail(email)) {
                return {
                    success: false,
                    message: 'Invalid email address'
                };
            }
            
            // Create new user
            const userId = this.generateUserId();
            const hashedPassword = this.hashPassword(password);
            
            const newUser = {
                id: userId,
                username,
                email,
                password: hashedPassword,
                role: 'user',
                createdAt: new Date().toISOString(),
                lastLogin: null
            };
            
            this.users.set(username, newUser);
            
            // Save users to file
            this.saveUsers();
            
            console.log(`User ${username} registered successfully`);
            
            return {
                success: true,
                message: 'Registration successful'
            };
            
        } catch (error) {
            console.error('Registration error:', error);
            return {
                success: false,
                message: 'Registration failed'
            };
        }
    }
    
    async logout(sessionId) {
        try {
            if (this.sessions.has(sessionId)) {
                this.sessions.delete(sessionId);
                console.log(`Session ${sessionId} terminated`);
                return { success: true };
            }
            
            return { success: false, message: 'Session not found' };
            
        } catch (error) {
            console.error('Logout error:', error);
            return { success: false, message: 'Logout failed' };
        }
    }
    
    verifyToken(token) {
        try {
            const decoded = jwt.verify(token, this.jwtSecret);
            return {
                valid: true,
                userId: decoded.userId,
                username: decoded.username,
                role: decoded.role
            };
        } catch (error) {
            return {
                valid: false,
                message: 'Invalid token'
            };
        }
    }
    
    validateSession(sessionId) {
        const session = this.sessions.get(sessionId);
        if (!session) {
            return { valid: false, message: 'Session not found' };
        }
        
        // Check session expiry (24 hours)
        const now = new Date();
        const sessionAge = now - session.createdAt;
        const maxAge = 24 * 60 * 60 * 1000; // 24 hours
        
        if (sessionAge > maxAge) {
            this.sessions.delete(sessionId);
            return { valid: false, message: 'Session expired' };
        }
        
        // Update last activity
        session.lastActivity = now;
        
        return {
            valid: true,
            userId: session.userId,
            username: session.username,
            role: session.role
        };
    }
    
    hashPassword(password) {
        const saltRounds = 10;
        return bcrypt.hashSync(password, saltRounds);
    }
    
    generateSessionId() {
        return 'sess_' + Math.random().toString(36).substr(2, 9) + Date.now().toString(36);
    }
    
    generateUserId() {
        return 'user_' + Math.random().toString(36).substr(2, 9) + Date.now().toString(36);
    }
    
    isValidEmail(email) {
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        return emailRegex.test(email);
    }
    
    saveUsers() {
        try {
            const usersDir = path.join(__dirname, '../data');
            if (!fs.existsSync(usersDir)) {
                fs.mkdirSync(usersDir, { recursive: true });
            }
            
            const usersArray = Array.from(this.users.values());
            const usersFile = path.join(usersDir, 'users.json');
            
            fs.writeFileSync(usersFile, JSON.stringify(usersArray, null, 2));
            console.log('Users saved to file');
            
        } catch (error) {
            console.error('Error saving users:', error);
        }
    }
    
    getUsers() {
        return Array.from(this.users.values()).map(user => ({
            id: user.id,
            username: user.username,
            email: user.email,
            role: user.role,
            createdAt: user.createdAt,
            lastLogin: user.lastLogin
        }));
    }
    
    getSessions() {
        return Array.from(this.sessions.entries()).map(([sessionId, session]) => ({
            sessionId,
            userId: session.userId,
            username: session.username,
            role: session.role,
            createdAt: session.createdAt,
            lastActivity: session.lastActivity
        }));
    }
    
    getStats() {
        return {
            totalUsers: this.users.size,
            activeSessions: this.sessions.size,
            tokenExpiry: this.tokenExpiry
        };
    }
}

module.exports = AuthenticationService;
