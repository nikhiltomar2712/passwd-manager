import React, { useState, useEffect, useRef } from 'react';
import { 
  Shield, 
  Key, 
  History, 
  BookOpen, 
  Eye, 
  EyeOff, 
  Clipboard, 
  Check, 
  AlertTriangle, 
  Cpu, 
  Globe, 
  Trash2, 
  Download, 
  RefreshCw, 
  X, 
  Sparkles,
  Info,
  CheckCircle2,
  XCircle,
  HelpCircle,
  Clock,
  ArrowRight
} from 'lucide-react';
import { 
  fullAnalysis, 
  generatePassword, 
  calculateEntropy, 
  estimateCrackTime, 
  analyzeComplexity, 
  detectPatterns, 
  calculateScore,
  suggestImprovements,
  checkBreach
} from './passwordUtils';

function App() {
  const [activeTab, setActiveTab] = useState('analyzer');
  const [sessionResults, setSessionResults] = useState([]);
  
  // Custom Toast state for clipboard/saves
  const [toast, setToast] = useState({ show: false, message: '' });
  const showToast = (message) => {
    setToast({ show: true, message });
    setTimeout(() => setToast({ show: false, message: '' }), 3000);
  };

  // --- ANALYZER STATE ---
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [checkHibp, setCheckHibp] = useState(true);
  const [analysisResult, setAnalysisResult] = useState(null);
  const [breachLoading, setBreachLoading] = useState(false);
  const [breachInfo, setBreachInfo] = useState({ checked: false, found: false, count: 0 });
  const breachTimeoutRef = useRef(null);

  // Analyze password locally instantly
  useEffect(() => {
    if (!password) {
      setAnalysisResult(null);
      setBreachInfo({ checked: false, found: false, count: 0 });
      return;
    }

    const complexity = analyzeComplexity(password);
    const entropy = calculateEntropy(password);
    const crackTime = estimateCrackTime(entropy);
    const patterns = detectPatterns(password);
    
    // Calculate intermediate score (excluding breach penalty until loaded)
    const { score, rating } = calculateScore(
      complexity,
      patterns,
      entropy,
      breachInfo.found ? breachInfo.count : 0
    );

    const suggestions = suggestImprovements(complexity, patterns, breachInfo.found);

    setAnalysisResult({
      complexity,
      entropy,
      crackTime,
      patterns,
      score,
      rating,
      suggestions
    });

    // Debounce the HIBP API lookup to avoid throttling
    if (checkTimeoutRef.current) clearTimeout(checkTimeoutRef.current);
    
    if (checkStatusRef.current) {
      // If password changed, mark breach status as stale/loading soon
      setBreachInfo(prev => ({ ...prev, checked: false }));
    }

    if (checkHibp) {
      setBreachLoading(true);
      checkTimeoutRef.current = setTimeout(async () => {
        const breach = await checkBreach(password);
        setBreachInfo(breach);
        setBreachLoading(false);
      }, 800); // 800ms debounce
    } else {
      setBreachLoading(false);
      setBreachInfo({ checked: false, found: false, count: 0 });
    }
  }, [password, checkHibp]);

  // Handle score update once breach info loads
  useEffect(() => {
    if (!password || !analysisResult) return;
    
    const { score, rating } = calculateScore(
      analysisResult.complexity,
      analysisResult.patterns,
      analysisResult.entropy,
      breachInfo.found ? breachInfo.count : 0
    );
    
    const suggestions = suggestImprovements(
      analysisResult.complexity,
      analysisResult.patterns,
      breachInfo.found
    );

    setAnalysisResult(prev => ({
      ...prev,
      score,
      rating,
      suggestions
    }));
  }, [breachInfo]);

  const checkTimeoutRef = useRef(null);
  const checkStatusRef = useRef(true);

  // Clean up timeouts
  useEffect(() => {
    return () => {
      if (checkTimeoutRef.current) clearTimeout(checkTimeoutRef.current);
    };
  }, []);

  const saveCurrentToHistory = () => {
    if (!password || !analysisResult) return;
    
    const historyEntry = {
      timestamp: new Date().toLocaleTimeString(),
      type: 'Analyzed',
      pwdLength: password.length,
      score: analysisResult.score,
      rating: analysisResult.rating,
      entropy: analysisResult.entropy,
      crackTime: analysisResult.crackTime,
      breached: breachInfo.found,
      breachCount: breachInfo.count,
      patternCount: analysisResult.patterns.length
    };
    
    setSessionResults(prev => [historyEntry, ...prev]);
    showToast('Analysis metadata saved to session logs');
  };

  // --- GENERATOR STATE ---
  const [genLength, setGenLength] = useState(16);
  const [genCount, setGenCount] = useState(1);
  const [opts, setOpts] = useState({
    upper: true,
    lower: true,
    digits: true,
    special: true
  });
  const [generatedList, setGeneratedList] = useState([]);
  const [copiedIndex, setCopiedIndex] = useState(null);

  const triggerGenerate = () => {
    const newList = [];
    for (let i = 0; i < genCount; i++) {
      const pwd = generatePassword(genLength, opts.upper, opts.lower, opts.digits, opts.special);
      const entropy = calculateEntropy(pwd);
      const crackTime = estimateCrackTime(entropy);
      const complexity = analyzeComplexity(pwd);
      const { score, rating } = calculateScore(complexity, [], entropy, 0);
      
      newList.push({
        password: pwd,
        score,
        rating,
        entropy,
        crackTime
      });
    }
    setGeneratedList(newList);
  };

  const copyToClipboard = (text, index = null) => {
    navigator.clipboard.writeText(text);
    if (index !== null) {
      setCopiedIndex(index);
      setTimeout(() => setCopiedIndex(null), 2000);
    }
    showToast('Password copied to clipboard!');
  };

  const saveGeneratedToHistory = (item) => {
    const historyEntry = {
      timestamp: new Date().toLocaleTimeString(),
      type: 'Generated',
      pwdLength: item.password.length,
      score: item.score,
      rating: item.rating,
      entropy: item.entropy,
      crackTime: item.crackTime,
      breached: false,
      breachCount: 0,
      patternCount: 0
    };
    
    setSessionResults(prev => [historyEntry, ...prev]);
    showToast('Password metadata saved to session logs');
  };

  // --- EXPORT/HISTORY ACTIONS ---
  const clearHistory = () => {
    setSessionResults([]);
    showToast('Session logs cleared');
  };

  const exportJSON = () => {
    if (sessionResults.length === 0) return;
    const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(
      JSON.stringify({
        exporter: "Password Strength Analyzer Web App",
        exportedAt: new Date().toISOString(),
        totalLogs: sessionResults.length,
        logs: sessionResults
      }, null, 2)
    );
    const downloadAnchor = document.createElement('a');
    downloadAnchor.setAttribute("href", dataStr);
    downloadAnchor.setAttribute("download", `psa_session_results_${Date.now()}.json`);
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();
  };

  const exportCSV = () => {
    if (sessionResults.length === 0) return;
    const headers = ['Timestamp', 'Type', 'Length', 'Score', 'Rating', 'Entropy (bits)', 'Crack Est', 'Breached', 'Breach Occurrences', 'Weak Patterns'];
    const csvRows = [headers.join(',')];
    
    for (const row of sessionResults) {
      const values = [
        `"${row.timestamp}"`,
        `"${row.type}"`,
        row.pwdLength,
        row.score,
        `"${row.rating}"`,
        row.entropy,
        `"${row.crackTime}"`,
        row.breached ? 'Yes' : 'No',
        row.breachCount,
        row.patternCount
      ];
      csvRows.push(values.join(','));
    }
    
    const dataStr = "data:text/csv;charset=utf-8," + encodeURIComponent(csvRows.join('\n'));
    const downloadAnchor = document.createElement('a');
    downloadAnchor.setAttribute("href", dataStr);
    downloadAnchor.setAttribute("download", `psa_session_results_${Date.now()}.csv`);
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();
  };

  // Run generation initially
  useEffect(() => {
    triggerGenerate();
  }, [genLength, opts, genCount]);

  // Color mapper based on HSL thresholds
  const getScoreColorClass = (score) => {
    if (score >= 80) return 'rgba(16, 185, 129, 1)'; // Green
    if (score >= 60) return 'rgba(52, 211, 153, 1)'; // Light Green
    if (score >= 40) return 'rgba(245, 158, 11, 1)'; // Amber
    if (score >= 20) return 'rgba(249, 115, 22, 1)'; // Orange
    return 'rgba(239, 68, 68, 1)'; // Red
  };

  const getScoreHue = (score) => {
    // Red (0) to green (120) transition in HSL
    return (score / 100) * 120;
  };

  return (
    <div className="app-container">
      {/* Toast Alert */}
      {toast.show && (
        <div style={{
          position: 'fixed',
          top: '20px',
          right: '20px',
          zIndex: 9999,
          background: 'rgba(18, 22, 31, 0.95)',
          border: '1px solid rgba(75, 103, 250, 0.4)',
          borderRadius: '10px',
          padding: '1rem 1.5rem',
          color: '#fff',
          boxShadow: '0 10px 25px rgba(0,0,0,0.3)',
          display: 'flex',
          alignItems: 'center',
          gap: '0.5rem',
          fontFamily: 'var(--font-display)',
          fontWeight: 600,
          fontSize: '0.9rem',
          backdropFilter: 'blur(10px)',
          animation: 'checkPop 0.2s cubic-bezier(0.175, 0.885, 0.32, 1.275)'
        }}>
          <CheckCircle2 size={18} color="#10b981" />
          {toast.message}
        </div>
      )}

      <header>
        <div className="logo-section">
          <h1>PASSWORD ANALYZER</h1>
          <span className="score-badge" style={{ backgroundColor: 'rgba(75, 103, 250, 0.25)', color: 'hsl(var(--accent-blue))' }}>v2.0 Web</span>
        </div>
        <p className="subtitle">Analyse · Generate · Audit Your Credentials Securely</p>
      </header>

      {/* Navigation tabs */}
      <nav className="tabs-navigation">
        <button 
          className={`tab-btn ${activeTab === 'analyzer' ? 'active' : ''}`}
          onClick={() => setActiveTab('analyzer')}
        >
          <Shield size={16} /> Analyzer
        </button>
        <button 
          className={`tab-btn ${activeTab === 'generator' ? 'active' : ''}`}
          onClick={() => setActiveTab('generator')}
        >
          <Key size={16} /> Generator
        </button>
        <button 
          className={`tab-btn ${activeTab === 'history' ? 'active' : ''}`}
          onClick={() => setActiveTab('history')}
        >
          <History size={16} /> Session Logs ({sessionResults.length})
        </button>
        <button 
          className={`tab-btn ${activeTab === 'about' ? 'active' : ''}`}
          onClick={() => setActiveTab('about')}
        >
          <BookOpen size={16} /> Education
        </button>
      </nav>

      {/* Main Content Area */}
      <main>
        {activeTab === 'analyzer' && (
          <div className="dashboard-grid">
            {/* Left Side: Inputs and complexity */}
            <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
              <div className="glass-card">
                <h2 className="card-title"><Shield color="hsl(var(--accent-blue))" size={20} /> Input Credentials</h2>
                
                <div className="input-group">
                  <div className="password-input-container">
                    <input 
                      type={showPassword ? "text" : "password"}
                      className="input-field"
                      placeholder="Type a password to analyze..."
                      value={password}
                      onChange={(e) => setPassword(e.target.value)}
                      autoFocus
                    />
                    {password && (
                      <button 
                        className="visibility-toggle" 
                        onClick={() => setPassword('')}
                        style={{ right: '3rem' }}
                        title="Clear input"
                      >
                        <X size={18} />
                      </button>
                    )}
                    <button 
                      className="visibility-toggle"
                      onClick={() => setShowPassword(!showPassword)}
                      title={showPassword ? "Mask password" : "Show password"}
                    >
                      {showPassword ? <EyeOff size={18} /> : <Eye size={18} />}
                    </button>
                  </div>
                </div>

                <div style={{ display: 'flex', gap: '1rem', alignItems: 'center', marginBottom: '1.5rem' }}>
                  <label className="checkbox-card" style={{ flex: 1, padding: '0.6rem 0.85rem' }} className={`checkbox-card ${checkHibp ? 'checked' : ''}`}>
                    <Globe size={16} className="checkbox-icon-wrapper" />
                    <span className="checkbox-title" style={{ fontSize: '0.8rem' }}>Check Breach Database (HIBP)</span>
                    <input 
                      type="checkbox"
                      checked={checkHibp}
                      onChange={(e) => setCheckHibp(e.target.checked)}
                      style={{ display: 'none' }}
                    />
                    <div className="custom-check">
                      {checkHibp && <Check size={12} strokeWidth={3} className="animate-check" />}
                    </div>
                  </label>
                  
                  {password && (
                    <button className="btn-icon-text" onClick={saveCurrentToHistory} title="Log this result">
                      <Download size={14} /> Log Session
                    </button>
                  )}
                </div>

                {analysisResult ? (
                  <div className="score-progress-container">
                    <div className="score-meta">
                      <span className="rating-text">
                        Rating: <span style={{ color: `hsl(${getScoreHue(analysisResult.score)}, 85%, 45%)` }}>{analysisResult.rating}</span>
                      </span>
                      <span className="score-text" style={{ color: `hsl(${getScoreHue(analysisResult.score)}, 85%, 45%)` }}>
                        {analysisResult.score}/100
                      </span>
                    </div>
                    <div className="score-bar-bg">
                      <div 
                        className="score-bar-fill" 
                        style={{ 
                          width: `${analysisResult.score}%`,
                          backgroundColor: `hsl(${getScoreHue(analysisResult.score)}, 85%, 45%)`,
                          boxShadow: `0 0 10px rgba(0,0,0,0.2), 0 0 4px hsl(${getScoreHue(analysisResult.score)}, 85%, 45%)`
                        }}
                      />
                    </div>
                  </div>
                ) : (
                  <div style={{ textAlign: 'center', padding: '1.5rem 0', color: 'var(--text-muted)', fontSize: '0.9rem' }}>
                    Provide a password to view strength scores & breakdowns.
                  </div>
                )}
              </div>

              {analysisResult && (
                <div className="glass-card">
                  <h3 className="card-title" style={{ fontSize: '1.1rem' }}><Cpu size={18} color="hsl(var(--accent-blue))" /> Character Composition</h3>
                  <div className="complexity-grid">
                    {[
                      { 
                        name: "Length (at least 12 characters, 16+ recommended)", 
                        passed: analysisResult.complexity.length >= 12, 
                        info: `${analysisResult.complexity.length} characters`
                      },
                      { 
                        name: "Uppercase characters (A–Z)", 
                        passed: analysisResult.complexity.hasUppercase, 
                        info: `${analysisResult.complexity.uppercaseCount} found` 
                      },
                      { 
                        name: "Lowercase characters (a–z)", 
                        passed: analysisResult.complexity.hasLowercase, 
                        info: `${analysisResult.complexity.lowercaseCount} found` 
                      },
                      { 
                        name: "Numeric digits (0–9)", 
                        passed: analysisResult.complexity.hasDigits, 
                        info: `${analysisResult.complexity.digitCount} found` 
                      },
                      { 
                        name: "Special symbols (!@#$%^&...)", 
                        passed: analysisResult.complexity.hasSpecial, 
                        info: `${analysisResult.complexity.specialCount} found` 
                      }
                    ].map((item, index) => (
                      <div key={index} className="complexity-item" style={{ borderLeft: item.passed ? '3px solid #10b981' : '3px solid #ef4444' }}>
                        <span className="complexity-label">
                          {item.passed ? <CheckCircle2 size={16} color="#10b981" /> : <XCircle size={16} color="#ef4444" />}
                          {item.name}
                        </span>
                        <span className="complexity-status" style={{ color: item.passed ? '#10b981' : 'var(--text-muted)' }}>
                          {item.info}
                        </span>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>

            {/* Right Side: Results, HIBP warning, Patterns, Suggestions */}
            <div>
              {analysisResult ? (
                <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
                  
                  {/* Entropy & Crack time */}
                  <div className="metrics-row">
                    <div className="metric-card">
                      <span className="metric-label"><Cpu size={14} /> Entropy</span>
                      <span className="metric-value">{analysisResult.entropy} Bits</span>
                      <span className="metric-desc">
                        {analysisResult.entropy >= 80 ? 'Excellent character variety' :
                         analysisResult.entropy >= 60 ? 'Good unpredictability' :
                         analysisResult.entropy >= 40 ? 'Fair character spread' : 'Poor random spread'}
                      </span>
                    </div>
                    <div className="metric-card">
                      <span className="metric-label"><Clock size={14} /> Crack Time</span>
                      <span className="metric-value" style={{ fontSize: '1.05rem', whiteSpace: 'nowrap', textOverflow: 'ellipsis', overflow: 'hidden' }}>{analysisResult.crackTime}</span>
                      <span className="metric-desc">Est. offline GPU hash brute force</span>
                    </div>
                  </div>

                  {/* HaveIBeenPwned Result */}
                  {checkHibp && (
                    <div className={`breach-status-card ${breachLoading ? '' : breachInfo.found ? 'breached' : 'safe'}`}>
                      {breachLoading ? (
                        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', color: 'var(--text-secondary)', fontSize: '0.9rem' }}>
                          <RefreshCw size={16} className="animate-spin" style={{ animation: 'spin 1s linear infinite' }} />
                          Querying HaveIBeenPwned database...
                        </div>
                      ) : breachInfo.checked ? (
                        breachInfo.found ? (
                          <>
                            <div className="breach-header" style={{ color: '#ef4444' }}>
                              <AlertTriangle size={20} /> DATA BREACH DETECTED!
                            </div>
                            <p style={{ fontSize: '0.85rem', color: '#fca5a5' }}>
                              This password appeared in known public data leaks <strong>{breachInfo.count.toLocaleString()}</strong> times. It is compromised and should never be used.
                            </p>
                          </>
                        ) : (
                          <>
                            <div className="breach-header" style={{ color: '#10b981' }}>
                              <Shield size={20} /> Clean Scan
                            </div>
                            <p style={{ fontSize: '0.85rem', color: '#a7f3d0' }}>
                              Not found in any known public database leaks. Secure via k-anonymity protocol.
                            </p>
                          </>
                        )
                      ) : (
                        <div style={{ fontSize: '0.85rem', color: 'var(--text-muted)' }}>
                          Breach checker idle.
                        </div>
                      )}
                    </div>
                  )}

                  {/* Pattern Warnings */}
                  <div className="glass-card">
                    <h3 className="card-title" style={{ fontSize: '1.1rem' }}><AlertTriangle size={18} color="#ef4444" /> Weakness Scanning</h3>
                    {analysisResult.patterns.length > 0 ? (
                      <div>
                        {analysisResult.patterns.map((issue, idx) => (
                          <div key={idx} className="warning-item">
                            <AlertTriangle size={14} style={{ flexShrink: 0, marginTop: '2px' }} />
                            <span>{issue}</span>
                          </div>
                        ))}
                      </div>
                    ) : (
                      <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', color: '#10b981', fontSize: '0.9rem', backgroundColor: 'rgba(16, 185, 129, 0.08)', border: '1px solid rgba(16, 185, 129, 0.2)', padding: '0.75rem', borderRadius: '8px' }}>
                        <Check size={16} /> No keyboard patterns, years, sequences or common names detected.
                      </div>
                    )}
                  </div>

                  {/* Actionable Suggestions */}
                  <div className="glass-card">
                    <h3 className="card-title" style={{ fontSize: '1.1rem' }}><Sparkles size={18} color="hsl(var(--accent-cyan))" /> Improvement Steps</h3>
                    <div>
                      {analysisResult.suggestions.map((suggestion, idx) => (
                        <div key={idx} className="suggestion-item">
                          <ArrowRight size={14} style={{ flexShrink: 0, marginTop: '3px', color: 'hsl(var(--accent-blue))' }} />
                          <span>{suggestion}</span>
                        </div>
                      ))}
                    </div>
                  </div>

                </div>
              ) : (
                <div className="glass-card" style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', padding: '4rem 2rem', color: 'var(--text-muted)', textAlign: 'center', height: '100%' }}>
                  <Info size={40} style={{ marginBottom: '1rem', color: 'var(--border-color)' }} />
                  <h4>Insight Summary Panel</h4>
                  <p style={{ fontSize: '0.85rem', marginTop: '0.5rem' }}>Metrics regarding cracking estimations, HaveIBeenPwned queries, and structural suggestion vectors will show here.</p>
                </div>
              )}
            </div>
          </div>
        )}

        {activeTab === 'generator' && (
          <div className="glass-card" style={{ maxWidth: '800px', margin: '0 auto' }}>
            <h2 className="card-title"><Key color="hsl(var(--accent-blue))" size={20} /> Cryptographically Secure Generator</h2>
            
            <div className="generator-layout">
              <div className="slider-group">
                <div className="slider-header">
                  <span className="slider-label">Password Length</span>
                  <span className="slider-value">{genLength}</span>
                </div>
                <input 
                  type="range"
                  min="8"
                  max="128"
                  value={genLength}
                  onChange={(e) => setGenLength(parseInt(e.target.value))}
                  className="range-input"
                />
              </div>

              <div className="slider-group" style={{ marginTop: '0.5rem' }}>
                <div className="slider-header">
                  <span className="slider-label">Bulk Generation Count</span>
                  <span className="slider-value">{genCount}</span>
                </div>
                <input 
                  type="range"
                  min="1"
                  max="20"
                  value={genCount}
                  onChange={(e) => setGenCount(parseInt(e.target.value))}
                  className="range-input"
                />
              </div>

              <div>
                <span className="slider-label" style={{ display: 'block', marginBottom: '0.75rem' }}>Character Parameters</span>
                <div className="checkbox-grid">
                  {[
                    { id: 'upper', title: 'Uppercase Letters', desc: 'Include A-Z alphabetic keys', icon: <Sparkles size={16} /> },
                    { id: 'lower', title: 'Lowercase Letters', desc: 'Include a-z alphabetic keys', icon: <Sparkles size={16} /> },
                    { id: 'digits', title: 'Numeric Digits', desc: 'Include 0-9 numerical digits', icon: <Sparkles size={16} /> },
                    { id: 'special', title: 'Special Symbols', desc: 'Include symbols (!@#$...)', icon: <Sparkles size={16} /> }
                  ].map((item) => (
                    <label 
                      key={item.id} 
                      className={`checkbox-card ${opts[item.id] ? 'checked' : ''}`}
                      onClick={() => setOpts(prev => ({ ...prev, [item.id]: !prev[item.id] }))}
                    >
                      <span className="checkbox-icon-wrapper">{item.icon}</span>
                      <div className="checkbox-info">
                        <span className="checkbox-title">{item.title}</span>
                        <span className="checkbox-desc">{item.desc}</span>
                      </div>
                      <div className="custom-check">
                        {opts[item.id] && <Check size={12} strokeWidth={3} className="animate-check" />}
                      </div>
                    </label>
                  ))}
                </div>
              </div>

              <div className="action-row">
                <button className="btn-primary" onClick={triggerGenerate}>
                  <RefreshCw size={18} /> Generate Passwords
                </button>
              </div>

              {generatedList.length > 0 && (
                <div className="gen-results-container">
                  <h3 style={{ fontFamily: 'var(--font-display)', fontSize: '1rem', fontWeight: 700, marginBottom: '0.5rem', color: 'var(--text-secondary)' }}>Generated Passwords</h3>
                  <div style={{ overflowX: 'auto' }}>
                    <table className="pwd-table">
                      <thead>
                        <tr>
                          <th style={{ width: '40px' }}>#</th>
                          <th>Secure Password</th>
                          <th>Score</th>
                          <th>Rating</th>
                          <th>Crack Est</th>
                          <th style={{ width: '100px' }}>Actions</th>
                        </tr>
                      </thead>
                      <tbody>
                        {generatedList.map((item, idx) => (
                          <tr key={idx}>
                            <td>{idx + 1}</td>
                            <td className="pwd-cell">{item.password}</td>
                            <td>
                              <span style={{ color: getScoreColorClass(item.score), fontWeight: '700' }}>
                                {item.score}
                              </span>
                            </td>
                            <td>{item.rating}</td>
                            <td style={{ color: 'var(--text-secondary)' }}>{item.crackTime}</td>
                            <td className="action-cell">
                              <button 
                                className={`btn-icon ${copiedIndex === idx ? 'copied' : ''}`}
                                onClick={() => copyToClipboard(item.password, idx)}
                                title="Copy to clipboard"
                              >
                                {copiedIndex === idx ? <Check size={16} /> : <Clipboard size={16} />}
                              </button>
                              <button 
                                className="btn-icon" 
                                onClick={() => saveGeneratedToHistory(item)}
                                title="Log result to history"
                              >
                                <Download size={16} />
                              </button>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              )}
            </div>
          </div>
        )}

        {activeTab === 'history' && (
          <div className="glass-card">
            <div className="history-header">
              <div>
                <h2 className="card-title"><History color="hsl(var(--accent-blue))" size={20} /> Session Audit Logs</h2>
                <p style={{ fontSize: '0.8rem', color: 'var(--text-muted)', marginTop: '0.2rem' }}>
                  Audited metadata is stored temporarily in local memory. Plan text credentials are <strong>never</strong> recorded.
                </p>
              </div>
              {sessionResults.length > 0 && (
                <div className="history-actions">
                  <button className="btn-icon-text" onClick={exportJSON}>
                    <Download size={14} /> Export JSON
                  </button>
                  <button className="btn-icon-text" onClick={exportCSV}>
                    <Download size={14} /> Export CSV
                  </button>
                  <button className="btn-icon-text" style={{ borderColor: 'rgba(239, 68, 68, 0.4)', color: '#fca5a5' }} onClick={clearHistory}>
                    <Trash2 size={14} /> Clear
                  </button>
                </div>
              )}
            </div>

            {sessionResults.length > 0 ? (
              <div style={{ overflowX: 'auto' }}>
                <table className="pwd-table">
                  <thead>
                    <tr>
                      <th>Time</th>
                      <th>Action</th>
                      <th>Length</th>
                      <th>Score</th>
                      <th>Rating</th>
                      <th>Entropy</th>
                      <th>Crack Time</th>
                      <th>HIBP Breach</th>
                      <th>Weak Patterns</th>
                    </tr>
                  </thead>
                  <tbody>
                    {sessionResults.map((row, idx) => (
                      <tr key={idx}>
                        <td style={{ color: 'var(--text-muted)', fontSize: '0.8rem' }}>{row.timestamp}</td>
                        <td>
                          <span style={{ 
                            fontSize: '0.75rem', 
                            padding: '0.15rem 0.5rem', 
                            borderRadius: '4px',
                            backgroundColor: row.type === 'Analyzed' ? 'rgba(75, 103, 250, 0.15)' : 'rgba(16, 185, 129, 0.15)',
                            color: row.type === 'Analyzed' ? 'hsl(var(--accent-blue))' : '#10b981',
                            fontWeight: '600'
                          }}>
                            {row.type}
                          </span>
                        </td>
                        <td>{row.pwdLength} chars</td>
                        <td style={{ fontWeight: '700', color: getScoreColorClass(row.score) }}>{row.score}</td>
                        <td>{row.rating}</td>
                        <td>{row.entropy} bits</td>
                        <td style={{ fontSize: '0.85rem', color: 'var(--text-secondary)' }}>{row.crackTime}</td>
                        <td>
                          {row.type === 'Generated' ? (
                            <span style={{ color: 'var(--text-muted)' }}>N/A</span>
                          ) : row.breached ? (
                            <span style={{ color: '#ef4444', fontWeight: 600 }}>Breached ({row.breachCount.toLocaleString()})</span>
                          ) : (
                            <span style={{ color: '#10b981' }}>Clean Scan</span>
                          )}
                        </td>
                        <td>
                          {row.patternCount > 0 ? (
                            <span style={{ color: '#f59e0b', fontWeight: 600 }}>{row.patternCount} issues</span>
                          ) : (
                            <span style={{ color: '#10b981' }}>None</span>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : (
              <div className="empty-state">
                <History size={48} />
                <h3>No Session Logs Yet</h3>
                <p style={{ fontSize: '0.85rem', maxWidth: '350px', margin: '0 auto' }}>
                  Analyze passwords in the Analyzer tab or save generated candidates in the Generator tab to populate metadata audit logs.
                </p>
              </div>
            )}
          </div>
        )}

        {activeTab === 'about' && (
          <div className="glass-card" style={{ maxWidth: '800px', margin: '0 auto' }}>
            <h2 className="card-title"><BookOpen color="hsl(var(--accent-blue))" size={20} /> Security Education Hub</h2>
            
            <div className="edu-layout">
              
              <div className="edu-section">
                <h3>What is Password Entropy?</h3>
                <p style={{ fontSize: '0.9rem', color: 'var(--text-secondary)' }}>
                  Entropy measures the absolute randomness and unpredictability of a password string in bits. It depends on two factors: the <strong>length of the password</strong> and the <strong>size of the character pool</strong> used (lowercase, uppercase, numbers, and symbols).
                </p>
                <div className="edu-grid">
                  <div className="edu-card">
                    <h4>Entropy Calculation Formula</h4>
                    <p style={{ fontStyle: 'italic', fontFamily: 'var(--font-mono)', fontSize: '0.85rem', color: 'var(--text-muted)', margin: '0.5rem 0' }}>
                      E = L × log₂(N)
                    </p>
                    <p style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>
                      Where <strong>L</strong> is the character length and <strong>N</strong> is the size of the character pool used (Lowercase: 26, Uppercase: 26, Numbers: 10, Symbols: 32).
                    </p>
                  </div>
                  <div className="edu-card">
                    <h4>Entropy Quality Scale</h4>
                    <ul style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', paddingLeft: '1rem', display: 'flex', flexDirection: 'column', gap: '0.25rem', marginTop: '0.25rem' }}>
                      <li><strong>80+ bits</strong>: Excellent — Extremely resilient</li>
                      <li><strong>60–80 bits</strong>: Good — Secure for standard users</li>
                      <li><strong>40–60 bits</strong>: Fair — Vulnerable to local dictionary attacks</li>
                      <li><strong>Under 40 bits</strong>: Poor — Easily cracked in seconds</li>
                    </ul>
                  </div>
                </div>
              </div>

              <div className="edu-section">
                <h3>HaveIBeenPwned & k-Anonymity</h3>
                <p style={{ fontSize: '0.9rem', color: 'var(--text-secondary)' }}>
                  This web app checks whether your password has been exposed in public database leaks using the HaveIBeenPwned API. To do this securely without exposing your credentials, we use the <strong>k-Anonymity model</strong>:
                </p>
                <div style={{ backgroundColor: 'var(--bg-secondary)', border: '1px solid var(--border-color)', borderRadius: '12px', padding: '1.25rem' }}>
                  <ol style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', paddingLeft: '1.25rem', display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
                    <li>The app computes the secure SHA-1 hash of the password locally in your browser. (e.g., <code>"password"</code> becomes <code>"5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8"</code>).</li>
                    <li>We send <strong>only the first 5 characters</strong> of the hash (<code>"5BAA6"</code>) to the HaveIBeenPwned API.</li>
                    <li>The API returns a list of suffix hashes that match those first 5 characters, along with their leak counts.</li>
                    <li>Your browser scans the returned suffixes to see if your full hash is on the list. <strong>Your plaintext password and full hash never leave this device.</strong></li>
                  </ol>
                </div>
              </div>

              <div className="edu-section">
                <h3>Strong Password Best Practices</h3>
                <ul style={{ fontSize: '0.9rem', color: 'var(--text-secondary)', paddingLeft: '1.25rem', display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
                  <li><strong>Length beats complexity:</strong> A 16-character password composed of simple words (e.g., <code>"coral-forest-lamp"</code>) is exponentially harder to crack than a 8-character password with random symbols (e.g., <code>"P@ss12!#"</code>).</li>
                  <li><strong>Avoid sequential patterns:</strong> Scanners easily detect alphabetical runs (<code>"abc"</code>, <code>"xyz"</code>), digit runs (<code>"12345"</code>), keyboard row patterns (<code>"qwerty"</code>), and palindromes.</li>
                  <li><strong>Use a Password Manager:</strong> Generate long, cryptographically secure passwords for every account, and record them in an encrypted vault.</li>
                  <li><strong>Enable Multi-Factor Authentication (MFA):</strong> Even if your password is stolen in a third-party breach, MFA prevents intruders from gaining unauthorized entry.</li>
                </ul>
              </div>

            </div>
          </div>
        )}
      </main>

      <footer>
        <p>🔐 Client-Side Password Strength Analyzer & Manager v2.0</p>
        <p style={{ color: 'var(--text-muted)', fontSize: '0.75rem' }}>
          Secure Design Policy: All calculations, cryptographic generations, and k-Anonymity checks are performed completely client-side in the sandbox of your browser. Passwords are never sent, saved, or leaked.
        </p>
      </footer>
    </div>
  );
}

export default App;
