import React, { useState, useEffect } from 'react';

const API_BASE = 'http://localhost:5000/api';

const isSelf = (user, targetUid) => {
  return user && user.uid === targetUid;
};

export default function App() {
  // Session State
  const [token, setToken] = useState(localStorage.getItem('token') || '');
  const [currentUser, setCurrentUser] = useState(JSON.parse(localStorage.getItem('user')) || null);

  // Auth UI State
  const [mobile, setMobile] = useState('');
  const [otp, setOtp] = useState('');
  const [otpSent, setOtpSent] = useState(false);
  const [authError, setAuthError] = useState('');
  const [authLoading, setAuthLoading] = useState(false);

  // App UI State
  const [users, setUsers] = useState([]);
  const [departments, setDepartments] = useState([]);
  const [selectedOU, setSelectedOU] = useState('ALL');
  const [searchQuery, setSearchQuery] = useState('');
  const [appError, setAppError] = useState('');
  const [appSuccess, setAppSuccess] = useState('');
  const [loading, setLoading] = useState(false);

  // Modals
  const [showAddModal, setShowAddModal] = useState(false);
  const [showEditModal, setShowEditModal] = useState(false);
  const [showDepartmentModal, setShowDepartmentModal] = useState(false);
  const [showGroupModal, setShowGroupModal] = useState(false);
  const [editUserData, setEditUserData] = useState(null);
  const [newUserData, setNewUserData] = useState({
    uid: '', cn: '', sn: '', mail: '', mobile: '',
    title: 'Employee', employeeType: 'active', businessCategory: 'USER',
    ou: '', userPassword: ''
  });
  const [newDepartmentName, setNewDepartmentName] = useState('');
  const [newGroupData, setNewGroupData] = useState({
    ou: '',
    cn: '',
    firstMemberUid: ''
  });
  const customDepartmentOption = '__custom_department__';

  // Security Simulation Logs
  const [securityLogs, setSecurityLogs] = useState([]);

  // Fetch initial data
  useEffect(() => {
    if (token) {
      fetchUsers();
      fetchDepartments();
    }
  }, [token]);

  // Log cleanouts after timeout
  useEffect(() => {
    if (appError) {
      const timer = setTimeout(() => setAppError(''), 6000);
      return () => clearTimeout(timer);
    }
  }, [appError]);

  useEffect(() => {
    if (appSuccess) {
      const timer = setTimeout(() => setAppSuccess(''), 4000);
      return () => clearTimeout(timer);
    }
  }, [appSuccess]);

  // --- API CALLS ---

  const handleSendOtp = async (e) => {
    e.preventDefault();
    if (!mobile) return;
    setAuthLoading(true);
    setAuthError('');
    try {
      const res = await fetch(`${API_BASE}/auth/otp/request`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ mobile })
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.message || 'Mobile number lookup failed');
      
      setOtpSent(true);
      setOtp('123456'); // Pre-fill mock OTP for testing ease
    } catch (err) {
      setAuthError(err.message);
    } finally {
      setAuthLoading(false);
    }
  };

  const handleVerifyOtp = async (e) => {
    e.preventDefault();
    if (!otp) return;
    setAuthLoading(true);
    setAuthError('');
    try {
      const res = await fetch(`${API_BASE}/auth/otp/verify`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ mobile, otp })
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.message || 'OTP verification failed');

      localStorage.setItem('token', data.token);
      localStorage.setItem('user', JSON.stringify(data.user));
      setToken(data.token);
      setCurrentUser(data.user);
      
      // Add system log
      addSecurityLog('SUCCESS', `User '${data.user.uid}' authenticated via mobile OTP. Bound service account tier.`, 'Backend Auth');
    } catch (err) {
      setAuthError(err.message);
    } finally {
      setAuthLoading(false);
    }
  };

  const handleLogout = () => {
    localStorage.removeItem('token');
    localStorage.removeItem('user');
    setToken('');
    setCurrentUser(null);
    setOtpSent(false);
    setMobile('');
    setOtp('');
    setUsers([]);
    setDepartments([]);
    setSecurityLogs([]);
  };

  const fetchUsers = async () => {
    setLoading(true);
    try {
      const res = await fetch(`${API_BASE}/users`, {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.message || 'Failed to fetch users');
      setUsers(data);
    } catch (err) {
      setAppError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const fetchDepartments = async () => {
    try {
      const res = await fetch(`${API_BASE}/departments`, {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      const data = await res.json();
      if (res.ok) {
        setDepartments(data);
      }
    } catch (err) {
      console.error(err);
    }
  };

  const handleCreateDepartment = async (e) => {
    e.preventDefault();
    setLoading(true);
    try {
      const res = await fetch(`${API_BASE}/departments`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify({ name: newDepartmentName })
      });
      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.message || 'Failed to create department');
      }

      setAppSuccess(data.message);
      setShowDepartmentModal(false);
      setNewDepartmentName('');
      fetchDepartments();
    } catch (err) {
      setAppError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const handleCreateGroup = async (e) => {
    e.preventDefault();
    setLoading(true);
    try {
      const payload = {
        ou: newGroupData.ou,
        cn: newGroupData.cn,
        memberUids: [newGroupData.firstMemberUid].filter(Boolean)
      };

      const res = await fetch(`${API_BASE}/groups`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify(payload)
      });
      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.message || 'Failed to create group');
      }

      setAppSuccess(data.message);
      setShowGroupModal(false);
      setNewGroupData({ ou: '', cn: '', firstMemberUid: '' });
      addSecurityLog('ALLOWED', `Created group '${newGroupData.cn}' under 'ou=${newGroupData.ou}'.`, 'Backend RBAC');
    } catch (err) {
      setAppError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const handleCreateUser = async (e) => {
    e.preventDefault();
    setLoading(true);
    try {
      const res = await fetch(`${API_BASE}/users`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify(newUserData)
      });
      const data = await res.json();
      if (!res.ok) {
        addSecurityLog('DENIED', `LDAP Write Blocked! Creation of user '${newUserData.uid}' in '${newUserData.ou}' rejected: ${data.message}`, 'LDAP ACL Container');
        throw new Error(data.message || 'Creation failed');
      }

      setAppSuccess(data.message);
      addSecurityLog('ALLOWED', `Successfully created user '${newUserData.uid}' under 'ou=${newUserData.ou}'.`, 'LDAP ACL Container');
      setShowAddModal(false);
      // Reset form
      setNewUserData({
        uid: '', cn: '', sn: '', mail: '', mobile: '',
        title: 'Employee', employeeType: 'active', businessCategory: 'USER',
        ou: '', userPassword: ''
      });
      fetchUsers();
    } catch (err) {
      setAppError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const selectedDepartmentValue =
    departments.some((department) => department.name === newUserData.ou)
      ? newUserData.ou
      : (newUserData.ou ? customDepartmentOption : '');

  const selectedEditDepartmentValue =
    departments.some((department) => department.name === editUserData?.ou)
      ? editUserData.ou
      : (editUserData?.ou ? customDepartmentOption : '');

  const visibleScopeLabel = currentUser?.role === 'SUPER_ADMIN'
    ? 'Global Scope'
    : currentUser?.role === 'ADMIN'
      ? currentUser.ou
      : 'Self Scope';

  const activeEntriesScopeLabel = currentUser?.role === 'SUPER_ADMIN'
    ? selectedOU
    : currentUser?.role === 'ADMIN'
      ? currentUser.ou
      : 'SELF';

  const handleUpdateUser = async (e) => {
    e.preventDefault();
    setLoading(true);
    try {
      const res = await fetch(`${API_BASE}/users/${editUserData.uid}`, {
        method: 'PUT',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify(editUserData)
      });
      const data = await res.json();
      if (!res.ok) {
        addSecurityLog('DENIED', `LDAP Modify Blocked! Update on uid='${editUserData.uid}' rejected: ${data.message}`, 'LDAP ACL Container');
        throw new Error(data.message || 'Update failed');
      }

      setAppSuccess(data.message);
      addSecurityLog('ALLOWED', `Successfully modified user properties for uid='${editUserData.uid}'.`, 'LDAP ACL Container');
      setShowEditModal(false);
      fetchUsers();
    } catch (err) {
      setAppError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const handleDeleteUser = async (uid, ou) => {
    if (!window.confirm(`Are you sure you want to delete user ${uid}?`)) return;
    setLoading(true);
    try {
      const res = await fetch(`${API_BASE}/users/${uid}?ou=${ou}`, {
        method: 'DELETE',
        headers: { 'Authorization': `Bearer ${token}` }
      });
      const data = await res.json();
      if (!res.ok) {
        addSecurityLog('DENIED', `LDAP Delete Blocked! Removal of user '${uid}' in 'ou=${ou}' rejected: ${data.message}`, 'LDAP ACL Container');
        throw new Error(data.message || 'Deletion failed');
      }

      setAppSuccess(data.message);
      addSecurityLog('ALLOWED', `Removed user '${uid}' from DIT under 'ou=${ou}'.`, 'LDAP ACL Container');
      fetchUsers();
    } catch (err) {
      setAppError(err.message);
    } finally {
      setLoading(false);
    }
  };

  // --- SECURITY SIMULATION HELPER ---

  const simulateCrossDepartmentBypass = async () => {
    // Audit Admin tries to write to Developer OU, or Developer Admin tries to write to Audit OU
    if (currentUser.role === 'SUPER_ADMIN') {
      alert("As a SUPER_ADMIN, you have global write rights! Log in as a department admin (e.g. Audit Admin) to test the security containment.");
      return;
    }

    const testOU = currentUser.ou.toLowerCase() === 'audit' ? 'developer' : 'audit';
    const mockUid = `bypass-tester-${Math.floor(Math.random() * 1000)}`;

    addSecurityLog('ATTEMPT', `Initiating Simulated REST Bypass: logged-in as admin of 'ou=${currentUser.ou}', sending creation payload for 'ou=${testOU}'.`, 'Simulation Console');

    try {
      // We send a request to create a user in a different OU
      const res = await fetch(`${API_BASE}/users`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify({
          uid: mockUid,
          cn: 'Security Test',
          sn: 'Tester',
          mail: 'test@company.com',
          mobile: '999999',
          ou: testOU, // Cross-department target
          title: 'Employee'
        })
      });

      const data = await res.json();

      if (res.status === 403) {
        addSecurityLog('DENIED', `Containment Successful! LDAP Server rejected modification under 'ou=${testOU}' with: ${data.message}`, 'LDAP ACL Container');
        setAppError(`Security Alert: LDAP ACL successfully blocked cross-OU write to "${testOU}"!`);
      } else {
        addSecurityLog('WARNING', `Bypass completed. OpenLDAP did not block the write. Response status: ${res.status}`, 'System Warning');
      }
    } catch (err) {
      console.error(err);
    }
  };

  const addSecurityLog = (status, details, source) => {
    const newLog = {
      timestamp: new Date().toLocaleTimeString(),
      status,
      details,
      source
    };
    setSecurityLogs(prev => [newLog, ...prev]);
  };

  /*
  // Quick Account Login Helper (speeds up E2E verification)
  const quickLogin = (phone) => {
    setMobile(phone);
    setOtpSent(true);
    setOtp('123456');
  };
  */

  // --- RENDER HELPERS ---

  const getServiceAccountString = () => {
    if (!currentUser) return 'None';
    return 'cn=admin,dc=company,dc=com';
  };

  const filteredUsers = users.filter(user => {
    const matchesOU = selectedOU === 'ALL' || user.ou.toLowerCase() === selectedOU.toLowerCase();
    const matchesSearch = user.uid.toLowerCase().includes(searchQuery.toLowerCase()) ||
                          user.cn.toLowerCase().includes(searchQuery.toLowerCase()) ||
                          user.mobile.includes(searchQuery);
    return matchesOU && matchesSearch;
  });

  return (
    <div className="app-container">
      {/* HEADER SECTION */}
      <header className="navbar glass-panel">
        <div className="nav-brand">
          <div className="nav-logo-icon">Ω</div>
          <div>
            <h1>BRldap</h1>
            <p style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Enterprise LDAP RBAC + ACL Manager</p>
          </div>
        </div>

        {currentUser && (
          <div className="nav-user-info">
            <span className="pulse-dot"></span>
            <div style={{ textAlign: 'right' }}>
              <div style={{ fontWeight: '700', fontSize: '0.9rem' }}>{currentUser.cn || currentUser.uid}</div>
              <div style={{ display: 'flex', gap: '0.4rem', alignItems: 'center' }}>
                <span className={`badge badge-${currentUser.role.toLowerCase()}`}>{currentUser.role}</span>
                <span style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>ou={currentUser.ou || 'Global'}</span>
              </div>
            </div>
            <button onClick={handleLogout} className="btn btn-secondary" style={{ padding: '0.5rem 1rem', fontSize: '0.85rem' }}>
              Logout
            </button>
          </div>
        )}
      </header>

      {appSuccess && (
        <div className="glass-panel" style={{ padding: '1rem', marginBottom: '1.5rem', borderLeft: '4px solid var(--status-success)', color: 'var(--status-success)', fontWeight: '600' }}>
          ✓ {appSuccess}
        </div>
      )}

      {appError && (
        <div className="glass-panel" style={{ padding: '1.25rem', marginBottom: '1.5rem', borderLeft: '4px solid var(--status-error)', background: 'rgba(239, 68, 68, 0.05)', color: 'var(--text-primary)' }}>
          <strong style={{ color: 'var(--status-error)', display: 'block', marginBottom: '0.25rem' }}>⚠ Security Action</strong>
          <span style={{ fontSize: '0.9rem', color: 'var(--text-secondary)' }}>{appError}</span>
        </div>
      )}

      {/* 1. AUTH / LOGIN VIEW */}
      {!token ? (
        <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '2rem', marginTop: '2rem' }}>
          <div className="glass-panel" style={{ width: '100%', maxWidth: '450px', padding: '2.5rem' }}>
            <h2 style={{ marginBottom: '0.5rem', textAlign: 'center' }}>Secure Gateway Access</h2>
            <p style={{ color: 'var(--text-muted)', fontSize: '0.85rem', textAlign: 'center', marginBottom: '2rem' }}>
              Verify identity using OTP validation. Dynamic directory roles mapping is fetched automatically.
            </p>

            {authError && (
              <div style={{ padding: '0.75rem', borderRadius: '8px', background: 'rgba(239,68,68,0.1)', border: '1px solid rgba(239,68,68,0.2)', color: 'var(--status-error)', fontSize: '0.85rem', marginBottom: '1.5rem', textAlign: 'center' }}>
                {authError}
              </div>
            )}

            {!otpSent ? (
              <form onSubmit={handleSendOtp}>
                <div className="form-group">
                  <label className="form-label">Registered Mobile Number</label>
                  <input
                    type="text"
                    required
                    className="form-input"
                    placeholder="Enter phone number..."
                    value={mobile}
                    maxLength={10}
                    inputMode="numeric"
                    pattern="[0-9]{10}"
                    onChange={(e) => setMobile(e.target.value.replace(/\D/g, '').slice(0, 10))}
                  />
                </div>
                <button type="submit" disabled={authLoading} className="btn btn-primary" style={{ width: '100%', justifyContent: 'center', marginTop: '0.5rem' }}>
                  {authLoading ? 'Verifying Phone...' : 'Request Verification OTP'}
                </button>
              </form>
            ) : (
              <form onSubmit={handleVerifyOtp}>
                <div className="form-group">
                  <label className="form-label">SMS Verification Code</label>
                  <input
                    type="text"
                    required
                    className="form-input"
                    placeholder="Enter 6-digit OTP..."
                    value={otp}
                    onChange={(e) => setOtp(e.target.value)}
                  />
                </div>
                <button type="submit" disabled={authLoading} className="btn btn-primary" style={{ width: '100%', justifyContent: 'center', marginTop: '0.5rem' }}>
                  {authLoading ? 'Authorizing Session...' : 'Verify & Enter Dashboard'}
                </button>
                <button type="button" onClick={() => setOtpSent(false)} className="btn btn-secondary" style={{ width: '100%', justifyContent: 'center', marginTop: '0.75rem' }}>
                  Change Phone Number
                </button>
              </form>
            )}
          </div>

          {/*
          <div className="glass-panel" style={{ width: '100%', maxWidth: '650px', padding: '1.5rem' }}>
            <h3 style={{ fontSize: '0.9rem', textTransform: 'uppercase', color: 'var(--accent-primary)', marginBottom: '1rem', letterSpacing: '0.05em' }}>
              ⚡ Sandbox Login Assist (DIT Pre-sets)
            </h3>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: '0.75rem' }}>
              <div onClick={() => quickLogin('6234567890')} style={{ padding: '0.75rem', borderRadius: '8px', border: '1px solid rgba(255,255,255,0.05)', cursor: 'pointer', background: 'rgba(255,255,255,0.02)' }} className="quick-login-card">
                <div style={{ fontWeight: '700', fontSize: '0.85rem' }}>Superadmin</div>
                <div style={{ color: 'var(--text-muted)', fontSize: '0.75rem' }}>Phone: 6234567890</div>
              </div>
              <div onClick={() => quickLogin('3289632')} style={{ padding: '0.75rem', borderRadius: '8px', border: '1px solid rgba(255,255,255,0.05)', cursor: 'pointer', background: 'rgba(255,255,255,0.02)' }} className="quick-login-card">
                <div style={{ fontWeight: '700', fontSize: '0.85rem', color: 'var(--accent-primary)' }}>Audit Admin (au1)</div>
                <div style={{ color: 'var(--text-muted)', fontSize: '0.75rem' }}>Phone: 3289632</div>
              </div>
              <div onClick={() => quickLogin('872836282')} style={{ padding: '0.75rem', borderRadius: '8px', border: '1px solid rgba(255,255,255,0.05)', cursor: 'pointer', background: 'rgba(255,255,255,0.02)' }} className="quick-login-card">
                <div style={{ fontWeight: '700', fontSize: '0.85rem', color: 'var(--accent-secondary)' }}>Dev Admin (imp2)</div>
                <div style={{ color: 'var(--text-muted)', fontSize: '0.75rem' }}>Phone: 872836282</div>
              </div>
              <div onClick={() => quickLogin('87897623')} style={{ padding: '0.75rem', borderRadius: '8px', border: '1px solid rgba(255,255,255,0.05)', cursor: 'pointer', background: 'rgba(255,255,255,0.02)' }} className="quick-login-card">
                <div style={{ fontWeight: '700', fontSize: '0.85rem' }}>Normal Employee (au3)</div>
                <div style={{ color: 'var(--text-muted)', fontSize: '0.75rem' }}>Phone: 87897623</div>
              </div>
            </div>
          </div>
          */}
        </div>
      ) : (
        /* 2. LOGGED IN DASHBOARD VIEW */
        <div className="dashboard-grid">
          
          {/* SIDEBAR */}
          <aside style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
            {/* Connection Information Panel */}
            <div className="glass-panel" style={{ padding: '1.25rem' }}>
              <h3 style={{ fontSize: '0.8rem', textTransform: 'uppercase', color: 'var(--text-muted)', marginBottom: '0.75rem' }}>Connection Security</h3>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
                <div>
                  <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>MAPPED SERVICE ACCOUNT</div>
                  <div style={{ fontSize: '0.75rem', fontFamily: 'monospace', color: 'var(--accent-primary)', wordBreak: 'break-all', marginTop: '0.2rem' }}>
                    {getServiceAccountString()}
                  </div>
                </div>
                <hr style={{ border: 'none', height: '1px', background: 'var(--border-glass)' }} />
                <div>
                  <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>PRIMARY GATEWAY LAYER</div>
                  <div style={{ fontSize: '0.8rem', fontWeight: '700', color: 'var(--status-success)', marginTop: '0.1rem' }}>Active (Backend RBAC)</div>
                </div>
                <div>
                  <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>CONTAINMENT LAYER</div>
                  <div style={{ fontSize: '0.8rem', fontWeight: '700', color: 'var(--status-success)', marginTop: '0.1rem' }}>Enforced (LDAP ACLs)</div>
                </div>
              </div>
            </div>

            {/* Department Filter (Only for Superadmins or users listing all) */}
            <div className="glass-panel" style={{ padding: '1.25rem' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.75rem' }}>
                <h3 style={{ fontSize: '0.8rem', textTransform: 'uppercase', color: 'var(--text-muted)' }}>Departments (OUs)</h3>
                {currentUser.role === 'SUPER_ADMIN' && (
                  <div style={{ display: 'flex', gap: '0.35rem' }}>
                    <button
                      onClick={() => setShowGroupModal(true)}
                      className="btn btn-secondary"
                      style={{ padding: '0.25rem 0.5rem', fontSize: '0.7rem' }}
                    >
                      + CN
                    </button>
                    <button
                      onClick={() => setShowDepartmentModal(true)}
                      className="btn btn-primary"
                      style={{ padding: '0.25rem 0.5rem', fontSize: '0.7rem' }}
                    >
                      + Add
                    </button>
                  </div>
                )}
              </div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '0.4rem' }}>
                {currentUser.role === 'SUPER_ADMIN' ? (
                  <>
                    <button
                      onClick={() => setSelectedOU('ALL')}
                      className={`btn ${selectedOU === 'ALL' ? 'btn-primary' : 'btn-secondary'}`}
                      style={{ width: '100%', justifyContent: 'flex-start', padding: '0.5rem 0.75rem', fontSize: '0.85rem' }}
                    >
                      🌐 {visibleScopeLabel}
                    </button>
                    {departments.map((dept) => (
                      <button
                        key={dept.dn}
                        onClick={() => setSelectedOU(dept.name)}
                        className={`btn ${selectedOU === dept.name ? 'btn-primary' : 'btn-secondary'}`}
                        style={{ width: '100%', justifyContent: 'flex-start', padding: '0.5rem 0.75rem', fontSize: '0.85rem' }}
                      >
                        📂 ou={dept.name}
                      </button>
                    ))}
                  </>
                ) : (
                  <button
                    className="btn btn-primary"
                    style={{ width: '100%', justifyContent: 'flex-start', padding: '0.5rem 0.75rem', fontSize: '0.85rem' }}
                  >
                    🔒 {visibleScopeLabel}
                  </button>
                )}
              </div>
            </div>

            {/* Security Simulation Actions */}
            {currentUser && currentUser.role !== 'SUPER_ADMIN' && (
              <div className="glass-panel" style={{ padding: '1.25rem', border: '1px dashed var(--accent-secondary)' }}>
                <h3 style={{ fontSize: '0.8rem', textTransform: 'uppercase', color: 'var(--accent-secondary)', marginBottom: '0.5rem' }}>Secondary Containment Test</h3>
                <p style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', marginBottom: '1rem' }}>
                  Verify that the LDAP server blocks cross-OU writes at the database layer even if the backend calls it.
                </p>
                <button onClick={simulateCrossDepartmentBypass} className="btn btn-danger" style={{ width: '100%', fontSize: '0.8rem', padding: '0.5rem' }}>
                  💣 Simulate ACL Bypass
                </button>
              </div>
            )}
          </aside>

          {/* MAIN CONTENT AREA */}
          <main style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
            
            {/* Quick Metrics */}
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '1rem' }}>
              <div className="glass-panel" style={{ padding: '1.25rem' }}>
                <div style={{ color: 'var(--text-muted)', fontSize: '0.8rem' }}>MANAGED DIRECTORY USERS</div>
                <div style={{ fontSize: '2rem', fontWeight: '800', color: 'white', margin: '0.25rem 0' }}>{users.length}</div>
                <div style={{ fontSize: '0.7rem', color: 'var(--accent-primary)' }}>Pulled from active subtrees</div>
              </div>
              <div className="glass-panel" style={{ padding: '1.25rem' }}>
                <div style={{ color: 'var(--text-muted)', fontSize: '0.8rem' }}>ACTIVE DEPARTMENTS (OUs)</div>
                <div style={{ fontSize: '2rem', fontWeight: '800', color: 'white', margin: '0.25rem 0' }}>{departments.length}</div>
                <div style={{ fontSize: '0.7rem', color: 'var(--accent-primary)' }}>Dynamic structural units</div>
              </div>
              <div className="glass-panel" style={{ padding: '1.25rem' }}>
                <div style={{ color: 'var(--text-muted)', fontSize: '0.8rem' }}>INTEGRITY HEALTH</div>
                <div style={{ fontSize: '1.25rem', fontWeight: '800', color: 'var(--status-success)', margin: '0.50rem 0' }}>100% Protected</div>
                <div style={{ fontSize: '0.7rem', color: 'var(--text-secondary)' }}>Secondary LDAP containment active</div>
              </div>
            </div>

            {/* DIT USERS MANAGEMENT */}
            <div className="glass-panel" style={{ padding: '1.5rem' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1.5rem', flexWrap: 'wrap', gap: '1rem' }}>
                <div>
                  <h2>Active DIT Entries</h2>
                  <p style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>Showing users under scope: {activeEntriesScopeLabel}</p>
                </div>

                <div style={{ display: 'flex', gap: '0.75rem', alignItems: 'center' }}>
                  <input
                    type="text"
                    className="form-input"
                    placeholder="Search UID or Name..."
                    value={searchQuery}
                    onChange={(e) => setSearchQuery(e.target.value)}
                    style={{ width: '220px', padding: '0.5rem 0.75rem', fontSize: '0.85rem' }}
                  />
                  {(currentUser.role === 'SUPER_ADMIN' || currentUser.role === 'ADMIN') && (
                    <button onClick={() => {
                      setNewUserData(prev => ({ ...prev, ou: currentUser.ou || 'audit' }));
                      setShowAddModal(true);
                    }} className="btn btn-primary" style={{ padding: '0.5rem 1rem', fontSize: '0.85rem' }}>
                      + Add DIT User
                    </button>
                  )}
                </div>
              </div>

              {/* Users table */}
              <div style={{ overflowX: 'auto' }}>
                {loading && users.length === 0 ? (
                  <p style={{ padding: '2rem', textAlign: 'center', color: 'var(--text-muted)' }}>Quering OpenLDAP...</p>
                ) : filteredUsers.length === 0 ? (
                  <p style={{ padding: '2rem', textAlign: 'center', color: 'var(--text-muted)' }}>No matching LDAP entries found.</p>
                ) : (
                  <table className="custom-table">
                    <thead>
                      <tr>
                        <th>UID</th>
                        <th>Name</th>
                        <th>Mobile</th>
                        <th>Email</th>
                        <th>Title</th>
                        <th>Role Badge</th>
                        <th>OU</th>
                        {currentUser.role !== 'USER' && <th style={{ textAlign: 'right' }}>Actions</th>}
                      </tr>
                    </thead>
                    <tbody>
                      {filteredUsers.map((u) => {
                        const isUserSelf = isSelf(currentUser, u.uid);
                        const userCanWrite = currentUser.role === 'SUPER_ADMIN' || 
                                             (currentUser.role === 'ADMIN' && currentUser.ou && u.ou && currentUser.ou.toLowerCase() === u.ou.toLowerCase());
                        
                        return (
                          <tr key={u.dn}>
                            <td style={{ fontFamily: 'monospace', fontWeight: '700' }}>{u.uid}</td>
                            <td>{u.cn}</td>
                            <td>{u.mobile}</td>
                            <td>{u.mail}</td>
                            <td>{u.title}</td>
                            <td>
                              <span className={`badge badge-${(u.businessCategory || 'USER').toLowerCase()}`}>
                                {u.businessCategory || 'USER'}
                              </span>
                            </td>
                            <td>
                              <span style={{ fontSize: '0.75rem', opacity: 0.8 }} className="badge badge-user">
                                ou={u.ou}
                              </span>
                            </td>
                            {currentUser.role !== 'USER' && (
                              <td style={{ textAlign: 'right' }}>
                                <div style={{ display: 'flex', gap: '0.5rem', justifyContent: 'flex-end' }}>
                                  {(isUserSelf || userCanWrite) && (
                                    <button
                                      onClick={() => {
                                        setEditUserData(u);
                                        setShowEditModal(true);
                                      }}
                                      className="btn btn-secondary"
                                      style={{ padding: '0.3rem 0.6rem', fontSize: '0.75rem' }}
                                    >
                                      Edit
                                    </button>
                                  )}
                                  {userCanWrite && !isUserSelf && (
                                    <button
                                      onClick={() => handleDeleteUser(u.uid, u.ou)}
                                      className="btn btn-danger"
                                      style={{ padding: '0.3rem 0.6rem', fontSize: '0.75rem' }}
                                    >
                                      Delete
                                    </button>
                                  )}
                                </div>
                              </td>
                            )}
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                )}
              </div>
            </div>

            {/* SECURITY LOGS VIEW */}
            <div className="glass-panel" style={{ padding: '1.5rem' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
                <div>
                  <h3>Real-time Security & ACL Access Log</h3>
                  <p style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Shows execution status under LDAP service-account switches</p>
                </div>
                <button onClick={() => setSecurityLogs([])} className="btn btn-secondary" style={{ padding: '0.3rem 0.6rem', fontSize: '0.75rem' }}>
                  Clear Logs
                </button>
              </div>

              <div style={{ maxHeight: '180px', overflowY: 'auto', background: 'rgba(0,0,0,0.2)', padding: '1rem', borderRadius: '8px', border: '1px solid var(--border-glass)' }}>
                {securityLogs.length === 0 ? (
                  <p style={{ fontSize: '0.8rem', color: 'var(--text-muted)', textAlign: 'center', padding: '1rem' }}>No system logs generated yet. Make modifications to see service account bindings.</p>
                ) : (
                  securityLogs.map((log, index) => (
                    <div key={index} style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.8rem', borderBottom: '1px solid rgba(255,255,255,0.03)', padding: '0.4rem 0', fontFamily: 'monospace' }}>
                      <span style={{ color: 'var(--text-muted)', width: '90px' }}>[{log.timestamp}]</span>
                      <span style={{ 
                        fontWeight: '700', 
                        width: '80px', 
                        color: log.status === 'ALLOWED' || log.status === 'SUCCESS' ? 'var(--status-success)' : log.status === 'DENIED' ? 'var(--status-error)' : 'var(--status-warning)' 
                      }}>
                        {log.status}
                      </span>
                      <span style={{ color: 'var(--text-secondary)', flex: 1, padding: '0 0.5rem' }}>{log.details}</span>
                      <span style={{ color: 'var(--accent-primary)', fontSize: '0.75rem' }}>{log.source}</span>
                    </div>
                  ))
                )}
              </div>
            </div>

          </main>
        </div>
      )}

      {/* --- ADD USER MODAL --- */}
      {showAddModal && (
        <div style={{ position: 'fixed', top: 0, left: 0, right: 0, bottom: 0, background: 'rgba(0,0,0,0.6)', display: 'flex', justifyContent: 'center', alignItems: 'center', zIndex: 1000, padding: '1rem' }}>
          <div className="glass-panel" style={{ width: '100%', maxWidth: '500px', padding: '2rem', maxHeight: '90vh', overflowY: 'auto' }}>
            <h3 style={{ marginBottom: '1.5rem' }}>Add New DIT User Profile</h3>
            <form onSubmit={handleCreateUser}>
              <div className="form-group">
                <label className="form-label">User ID (uid)</label>
                <input type="text" required className="form-input" value={newUserData.uid} onChange={e => setNewUserData({...newUserData, uid: e.target.value})} placeholder="e.g. au12" />
              </div>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem' }}>
                <div className="form-group">
                  <label className="form-label">First Name (cn)</label>
                  <input type="text" required className="form-input" value={newUserData.cn} onChange={e => setNewUserData({...newUserData, cn: e.target.value})} placeholder="First name" />
                </div>
                <div className="form-group">
                  <label className="form-label">Last Name (sn)</label>
                  <input type="text" required className="form-input" value={newUserData.sn} onChange={e => setNewUserData({...newUserData, sn: e.target.value})} placeholder="Last name" />
                </div>
              </div>
              <div className="form-group">
                <label className="form-label">Email Address</label>
                <input type="email" required className="form-input" value={newUserData.mail} onChange={e => setNewUserData({...newUserData, mail: e.target.value})} placeholder="user@gmail.com" />
              </div>
              <div className="form-group">
                <label className="form-label">Mobile Number</label>
                <input type="text" className="form-input" value={newUserData.mobile} onChange={e => setNewUserData({...newUserData, mobile: e.target.value})} placeholder="Phone number" />
              </div>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem' }}>
                <div className="form-group">
                  <label className="form-label">Title</label>
                  <input type="text" className="form-input" value={newUserData.title} onChange={e => setNewUserData({...newUserData, title: e.target.value})} />
                </div>
                <div className="form-group">
                  <label className="form-label">Role Category</label>
                  <select className="form-input" style={{ background: 'var(--bg-main)' }} value={newUserData.businessCategory} onChange={e => setNewUserData({...newUserData, businessCategory: e.target.value})}>
                    <option value="USER">USER</option>
                    <option value="ADMIN">ADMIN</option>
                    <option value="SUPER_ADMIN">SUPER_ADMIN</option>
                  </select>
                </div>
              </div>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem' }}>
                <div className="form-group">
                  <label className="form-label">Department (OU)</label>
                  {currentUser.role === 'SUPER_ADMIN' ? (
                    <>
                      <select
                        required
                        className="form-input"
                        style={{ background: 'var(--bg-main)' }}
                        value={selectedDepartmentValue}
                        onChange={(e) => setNewUserData({
                          ...newUserData,
                          ou: e.target.value === customDepartmentOption ? '' : e.target.value
                        })}
                      >
                        <option value="">Select department</option>
                        {departments.map((department) => (
                          <option key={department.dn} value={department.name}>{department.name}</option>
                        ))}
                        <option value={customDepartmentOption}>Other / Create new</option>
                      </select>
                      {selectedDepartmentValue === customDepartmentOption && (
                        <input
                          type="text"
                          required
                          className="form-input"
                          value={newUserData.ou}
                          onChange={e => setNewUserData({ ...newUserData, ou: e.target.value })}
                          placeholder="Enter new department"
                          style={{ marginTop: '0.75rem' }}
                        />
                      )}
                    </>
                  ) : (
                    <input 
                      type="text" 
                      className="form-input" 
                      value={currentUser.ou} 
                      disabled
                      style={{ background: 'var(--bg-muted)' }}
                    />
                  )}
                </div>
                <div className="form-group">
                  <label className="form-label">Password</label>
                  <input type="password" className="form-input" value={newUserData.userPassword} onChange={e => setNewUserData({...newUserData, userPassword: e.target.value})} placeholder="Set password" />
                </div>
              </div>
              
              <div style={{ display: 'flex', gap: '0.75rem', justifyContent: 'flex-end', marginTop: '1.5rem' }}>
                <button type="button" onClick={() => setShowAddModal(false)} className="btn btn-secondary">Cancel</button>
                <button type="submit" className="btn btn-primary">Create Profile</button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* --- EDIT USER MODAL --- */}
      {showEditModal && editUserData && (
        <div style={{ position: 'fixed', top: 0, left: 0, right: 0, bottom: 0, background: 'rgba(0,0,0,0.6)', display: 'flex', justifyContent: 'center', alignItems: 'center', zIndex: 1000, padding: '1rem' }}>
          <div className="glass-panel" style={{ width: '100%', maxWidth: '500px', padding: '2rem', maxHeight: '90vh', overflowY: 'auto' }}>
            <h3 style={{ marginBottom: '1.5rem' }}>Edit DIT User: {editUserData.uid}</h3>
            <form onSubmit={handleUpdateUser}>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem' }}>
                <div className="form-group">
                  <label className="form-label">First Name (cn)</label>
                  <input type="text" required className="form-input" value={editUserData.cn} onChange={e => setEditUserData({...editUserData, cn: e.target.value})} />
                </div>
                <div className="form-group">
                  <label className="form-label">Last Name (sn)</label>
                  <input type="text" required className="form-input" value={editUserData.sn} onChange={e => setEditUserData({...editUserData, sn: e.target.value})} />
                </div>
              </div>
              <div className="form-group">
                <label className="form-label">Email Address</label>
                <input type="email" required className="form-input" value={editUserData.mail} onChange={e => setEditUserData({...editUserData, mail: e.target.value})} />
              </div>
              <div className="form-group">
                <label className="form-label">Mobile Number</label>
                <input type="text" className="form-input" value={editUserData.mobile} onChange={e => setEditUserData({...editUserData, mobile: e.target.value})} />
              </div>
              <div className="form-group">
                <label className="form-label">Title</label>
                <input type="text" className="form-input" value={editUserData.title} onChange={e => setEditUserData({...editUserData, title: e.target.value})} />
              </div>

              {currentUser.role === 'SUPER_ADMIN' && (
                <div className="form-group">
                  <label className="form-label">Department (OU)</label>
                  <>
                    <select
                      required
                      className="form-input"
                      style={{ background: 'var(--bg-main)' }}
                      value={selectedEditDepartmentValue}
                      onChange={(e) => setEditUserData({
                        ...editUserData,
                        ou: e.target.value === customDepartmentOption ? '' : e.target.value
                      })}
                    >
                      <option value="">Select department</option>
                      {departments.map((department) => (
                        <option key={department.dn} value={department.name}>{department.name}</option>
                      ))}
                      <option value={customDepartmentOption}>Other / Create new</option>
                    </select>
                    {selectedEditDepartmentValue === customDepartmentOption && (
                      <input
                        type="text"
                        required
                        className="form-input"
                        value={editUserData.ou}
                        onChange={e => setEditUserData({ ...editUserData, ou: e.target.value })}
                        placeholder="Enter new department"
                        style={{ marginTop: '0.75rem' }}
                      />
                    )}
                  </>
                </div>
              )}
              
              {/* Only admins can modify user status / level */}
              {currentUser.role !== 'USER' && (
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem' }}>
                  <div className="form-group">
                    <label className="form-label">Role Category</label>
                    <select className="form-input" style={{ background: 'var(--bg-main)' }} value={editUserData.businessCategory} onChange={e => setEditUserData({...editUserData, businessCategory: e.target.value})}>
                      <option value="USER">USER</option>
                      <option value="ADMIN">ADMIN</option>
                      <option value="SUPER_ADMIN">SUPER_ADMIN</option>
                    </select>
                  </div>
                  <div className="form-group">
                    <label className="form-label">Status (employeeType)</label>
                    <select className="form-input" style={{ background: 'var(--bg-main)' }} value={editUserData.employeeType} onChange={e => setEditUserData({...editUserData, employeeType: e.target.value})}>
                      <option value="active">Active</option>
                      <option value="inactive">Inactive</option>
                    </select>
                  </div>
                </div>
              )}

              <div className="form-group">
                <label className="form-label">Password Reset (Leave blank to keep current)</label>
                <input type="password" className="form-input" value={editUserData.userPassword || ''} onChange={e => setEditUserData({...editUserData, userPassword: e.target.value})} placeholder="Enter new password" />
              </div>

              <div style={{ display: 'flex', gap: '0.75rem', justifyContent: 'flex-end', marginTop: '1.5rem' }}>
                <button type="button" onClick={() => setShowEditModal(false)} className="btn btn-secondary">Cancel</button>
                <button type="submit" className="btn btn-primary">Save Changes</button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* --- ADD DEPARTMENT MODAL --- */}
      {showDepartmentModal && (
        <div style={{ position: 'fixed', top: 0, left: 0, right: 0, bottom: 0, background: 'rgba(0,0,0,0.6)', display: 'flex', justifyContent: 'center', alignItems: 'center', zIndex: 1000, padding: '1rem' }}>
          <div className="glass-panel" style={{ width: '100%', maxWidth: '400px', padding: '2rem' }}>
            <h3 style={{ marginBottom: '1.5rem' }}>Add New Department (OU)</h3>
            <form onSubmit={handleCreateDepartment}>
              <div className="form-group">
                <label className="form-label">Department Name</label>
                <input 
                  type="text" 
                  required 
                  className="form-input" 
                  value={newDepartmentName} 
                  onChange={e => setNewDepartmentName(e.target.value)} 
                  placeholder="e.g. marketing, finance, hr" 
                />
                <p style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: '0.5rem' }}>
                  This will create a new organizational unit (OU) in LDAP.
                </p>
              </div>
              <div style={{ display: 'flex', gap: '0.75rem', justifyContent: 'flex-end', marginTop: '1.5rem' }}>
                <button type="button" onClick={() => setShowDepartmentModal(false)} className="btn btn-secondary">Cancel</button>
                <button type="submit" className="btn btn-primary">Create Department</button>
              </div>
            </form>
          </div>
        </div>
      )}

      {showGroupModal && (
        <div style={{ position: 'fixed', top: 0, left: 0, right: 0, bottom: 0, background: 'rgba(0,0,0,0.6)', display: 'flex', justifyContent: 'center', alignItems: 'center', zIndex: 1000, padding: '1rem' }}>
          <div className="glass-panel" style={{ width: '100%', maxWidth: '420px', padding: '2rem' }}>
            <h3 style={{ marginBottom: '1.5rem' }}>Create Group CN</h3>
            <form onSubmit={handleCreateGroup}>
              <div className="form-group">
                <label className="form-label">Department (OU)</label>
                <select
                  required
                  className="form-input"
                  style={{ background: 'var(--bg-main)' }}
                  value={newGroupData.ou}
                  onChange={(e) => setNewGroupData({ ...newGroupData, ou: e.target.value })}
                >
                  <option value="">Select department</option>
                  {departments.map((department) => (
                    <option key={department.dn} value={department.name}>{department.name}</option>
                  ))}
                </select>
              </div>
              <div className="form-group">
                <label className="form-label">Group CN</label>
                <input
                  type="text"
                  required
                  className="form-input"
                  value={newGroupData.cn}
                  onChange={e => setNewGroupData({ ...newGroupData, cn: e.target.value })}
                  placeholder="e.g. developers_admins"
                />
              </div>
              <div className="form-group">
                <label className="form-label">First Member UID</label>
                <input
                  type="text"
                  required
                  className="form-input"
                  value={newGroupData.firstMemberUid}
                  onChange={e => setNewGroupData({ ...newGroupData, firstMemberUid: e.target.value })}
                  placeholder="e.g. imp1"
                />
                <p style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: '0.5rem' }}>
                  LDAP `groupOfNames` needs at least one member when created.
                </p>
              </div>
              <div style={{ display: 'flex', gap: '0.75rem', justifyContent: 'flex-end', marginTop: '1.5rem' }}>
                <button type="button" onClick={() => setShowGroupModal(false)} className="btn btn-secondary">Cancel</button>
                <button type="submit" className="btn btn-primary">Create CN</button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}

