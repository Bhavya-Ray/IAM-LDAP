import express from 'express';
import session from 'express-session';
import cors from 'cors';
import dotenv from 'dotenv';
import jwt from 'jsonwebtoken';
import ldap from 'ldapjs';
import {
  executeLDAP,
  getServiceAccount,
  ldapSearch,
  ldapAdd,
  ldapModify,
  ldapDelete,
  ldapModifyDN
} from './config/ldap.js';
import { authMiddleware } from './middleware/auth.js';
import {
  requireManageOU,
  requireSelfOrAdmin,
  canManageOU,
  isSelf
} from './middleware/rbac.js';

dotenv.config();

const app = express();

const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || 'enterprise_ldap_rbac_acl_jwt_secret_2026';
const BASE_DN = process.env.LDAP_BASE_DN || 'dc=company,dc=com';
const LDAP_INFRA_OU = process.env.LDAP_INFRA_OU || 'ou=infra,dc=company,dc=com';
app.use(cors());
app.use(express.json());

// Basic logging middleware
app.use((req, res, next) => {
  console.log(`[${new Date().toISOString()}] ${req.method} ${req.url}`);
  next();
});

/**
 * Helper to parse OU from an LDAP Distinguished Name (DN)
 */
const getOUFromDN = (dn) => {
  const match = dn.match(/ou=([^,]+)/i);
  return match ? match[1] : null;
};

const getGroupDN = (cn, ou) => `cn=${cn},ou=${ou},${BASE_DN}`;
const getUserDN = (uid, ou) => `uid=${uid},ou=${ou},${BASE_DN}`;

const escapeLDAPFilterValue = (value = '') => {
  return value
    .replace(/\\/g, '\\5c')
    .replace(/\*/g, '\\2a')
    .replace(/\(/g, '\\28')
    .replace(/\)/g, '\\29')
    .replace(/\0/g, '\\00');
};

const getOUAdminGroupCNs = (ou) => {
  const normalizedOU = (ou || '').toLowerCase().trim();
  if (!normalizedOU) {
    return [];
  }

  const candidates = [
    `${normalizedOU}_admins`,
    `${normalizedOU}s_admins`
  ];

  return [...new Set(candidates)];
};

/**
 * Standard mapper to convert raw LDAP attributes into clean user JSON object
 */
const mapLDAPUser = (entry) => {
  return {
    dn: entry.dn,
    uid: entry.uid || '',
    cn: entry.cn || '',
    sn: entry.sn || '',
    mail: entry.mail || '',
    mobile: entry.mobile || '',
    title: entry.title || '',
    employeeType: entry.employeeType || '',
    businessCategory: entry.businessCategory || 'USER', // Acts as Role
    departmentNumber: entry.departmentNumber || '',
    labeledURI: entry.labeledURI || '',
    ou: getOUFromDN(entry.dn)
  };
};

const resolveEffectiveRole = async (client, mappedUser) => {

  const declaredRole =
    (mappedUser.businessCategory || 'USER').toUpperCase();

  // ------------------------------------------------
  // SUPER ADMIN
  // ------------------------------------------------

  if (declaredRole === 'SUPER_ADMIN') {
    return 'SUPER_ADMIN';
  }

  // ------------------------------------------------
  // SYSTEM OUs
  // ------------------------------------------------

  if (
    !mappedUser.ou ||
    ['managers', 'services'].includes(
      mappedUser.ou.toLowerCase()
    )
  ) {
    return 'USER';
  }

  // ------------------------------------------------
  // BUILD ADMIN GROUP NAMES
  // ------------------------------------------------

  const adminGroupCNs =
    getOUAdminGroupCNs(mappedUser.ou);

  if (adminGroupCNs.length === 0) {
    return 'USER';
  }

  const cnFilter =
    adminGroupCNs
      .map((cn) =>
        `(cn=${escapeLDAPFilterValue(cn)})`
      )
      .join('');

  // ------------------------------------------------
  // DEBUG LOGS
  // ------------------------------------------------

  console.log("ROLE CHECK USER DN:", mappedUser.dn);

  console.log(
    "ROLE FILTER:",
    `(&(objectClass=groupOfNames)(member=${mappedUser.dn})(|${cnFilter}))`
  );

  // ------------------------------------------------
  // SEARCH GROUPS
  // ------------------------------------------------

  const groups = await ldapSearch(
    client,
    `ou=${mappedUser.ou},${BASE_DN}`,
    {
      filter:
        `(&(objectClass=groupOfNames)` +
        `(member=${mappedUser.dn})` +
        `(|${cnFilter}))`,

      scope: 'one'
    }
  );

  console.log("GROUPS FOUND:", groups);

  // ------------------------------------------------
  // ROLE DECISION
  // ------------------------------------------------

  return groups.length > 0
    ? 'ADMIN'
    : 'USER';
};

const requireSuperAdmin = (req, res, next) => {
  if (req.user?.role !== 'SUPER_ADMIN') {
    return res.status(403).json({ message: 'Only SUPER_ADMIN can perform this action.' });
  }
  return next();
};

const findOUAdminGroups = async (client, ou) => {
  const adminGroupCNs = getOUAdminGroupCNs(ou);
  if (!ou || adminGroupCNs.length === 0) {
    return [];
  }

  const cnFilter = adminGroupCNs.map((cn) => `(cn=${escapeLDAPFilterValue(cn)})`).join('');
  return ldapSearch(client, `ou=${ou},${BASE_DN}`, {
    filter: `(&(objectClass=groupOfNames)(|${cnFilter}))`,
    scope: 'one'
  });
};

const syncOUAdminGroupMembership = async (client, userDN, ou, shouldBeAdmin) => {
  const adminGroups = await findOUAdminGroups(client, ou);
  if (adminGroups.length === 0) {
    if (shouldBeAdmin) {
      throw new Error(`No admin CN group exists for ou=${ou}. Create the CN first.`);
    }
    return;
  }

  for (const group of adminGroups) {
    const members = group.member
      ? (Array.isArray(group.member) ? group.member : [group.member])
      : [];
    const normalizedUserDN = userDN.toLowerCase().trim();
    const isMember = members.some((memberDN) => memberDN.toLowerCase().trim() === normalizedUserDN);

    if (shouldBeAdmin && !isMember) {
      try {
        await ldapModify(client, group.dn, [
          new ldap.Change({
            operation: 'add',
            modification: new ldap.Attribute({
              type: 'member',
              values: [userDN]
            })
          })
        ]);
      } catch (error) {
        if (error.name !== 'AttributeOrValueExistsError' && !error.message.includes('Attribute Or Value Exists')) {
          throw error;
        }
      }
    }

    if (!shouldBeAdmin && isMember) {
      try {
        await ldapModify(client, group.dn, [
          new ldap.Change({
            operation: 'delete',
            modification: new ldap.Attribute({
              type: 'member',
              values: [userDN]
            })
          })
        ]);
      } catch (error) {
        if (error.name !== 'NoSuchAttributeError' && !error.message.includes('No such attribute')) {
          throw error;
        }
      }
    }
  }
};

// --- AUTHENTICATION ENDPOINTS ---

/**
 * OTP Request: Look up user by mobile number.
 * Binds as low-privilege `ldap_reader`.
 */
app.post('/api/auth/otp/request', async (req, res) => {
  const { mobile } = req.body;
  if (!mobile) {
    return res.status(400).json({ message: 'Mobile number is required' });
  }

  try {
    const readerAccount = await getServiceAccount(null); // Guest reader

    const users = await executeLDAP(readerAccount.dn, readerAccount.password, async (client) => {
      return await ldapSearch(client, BASE_DN, {
        filter: `(&(objectClass=person)(mobile=${mobile}))`,
        scope: 'sub'
      });
    });

    if (users.length === 0) {
      return res.status(404).json({ message: 'No profile found matching this mobile number.' });
    }

    const user = mapLDAPUser(users[0]);
    console.log(`[OTP] Sent verification OTP (123456) to ${mobile} (uid=${user.uid})`);

    return res.json({
      message: 'OTP sent successfully',
      mobile: mobile,
      testOtp: '123456' // For test environment convenience
    });

  } catch (error) {
    console.error('OTP request error:', error);
    return res.status(500).json({ message: 'Failed to initiate OTP validation', error: error.message });
  }
});

/**
 * OTP Verify: Validate mock OTP and generate JWT containing user DIT scopes.
 */
app.post('/api/auth/otp/verify', async (req, res) => {
  const { mobile, otp } = req.body;

  if (!mobile || !otp) {
    return res.status(400).json({ message: 'Mobile and OTP are required' });
  }

  // Enforce requested fixed OTP restriction
  if (otp !== '123456') {
    return res.status(400).json({ message: 'Invalid verification code.' });
  }

  try {
    const readerAccount = await getServiceAccount(null);

    const users = await executeLDAP(readerAccount.dn, readerAccount.password, async (client) => {
      return await ldapSearch(client, BASE_DN, {
        filter: `(&(objectClass=person)(mobile=${mobile}))`,
        scope: 'sub'
      });
    });

    if (users.length === 0) {
      return res.status(404).json({ message: 'User not found' });
    }

    const matchedUser = mapLDAPUser(users[0]);
    const role = await executeLDAP(readerAccount.dn, readerAccount.password, async (client) => {
      return resolveEffectiveRole(client, matchedUser);
    });
    const tokenPayload = {
      uid: String(matchedUser.uid).trim().toLowerCase(),
      mobile: matchedUser.mobile,
      ou: String(matchedUser.ou).trim().toLowerCase(),
      role: role,
      dn: matchedUser.dn
    };

    const token = jwt.sign(tokenPayload, JWT_SECRET, { expiresIn: '8h' });

    return res.json({
      message: 'Authentication successful',
      token,
      user: {
        uid: matchedUser.uid,
        cn: matchedUser.cn,
        mail: matchedUser.mail,
        mobile: matchedUser.mobile,
        role: role,
        ou: matchedUser.ou,
        title: matchedUser.title,
        dn: matchedUser.dn
      }
    });

  } catch (error) {
    console.error('OTP verify error:', error);
    return res.status(500).json({ message: 'Verification failed', error: error.message });
  }
});


// --- USER MANAGEMENT ENDPOINTS ---

/**
 * Fetch list of departments/OUs.
 * Uses current logged-in user's mapped service account.
 */
app.get('/api/departments', authMiddleware, async (req, res) => {
  const svc = await getServiceAccount(req.user);

  try {
    const ous = await executeLDAP(svc.dn, svc.password, async (client) => {
      const results = await ldapSearch(client, BASE_DN, {
        filter: '(objectClass=organizationalUnit)',
        scope: 'one'
      });
      return results.map(entry => ({
        dn: entry.dn,
        name: entry.ou || getOUFromDN(entry.dn)
      })).filter(ou => ou.name !== 'services'); // Hide services OU
    });

    return res.json(ous);
  } catch (error) {
    return res.status(500).json({ message: 'Failed to retrieve departments', error: error.message });
  }
});

/**
 * Create a new OU (department).
 * Only SUPER_ADMIN can create new OUs.
 */
app.post('/api/departments', authMiddleware, async (req, res) => {
  const { name } = req.body;

  const normalizedName = String(name).trim().toLowerCase();
  if (!normalizedName) {
    return res.status(400).json({ message: 'Department name is required' });
  }

  // Only SUPER_ADMIN can create new OUs
  if (req.user.role !== 'SUPER_ADMIN') {
    return res.status(403).json({ message: 'Only SUPER_ADMIN can create new departments' });
  }

  const ouDN = `ou=${normalizedName},${BASE_DN}`;
  const svc = await getServiceAccount(req.user);

  const entry = {
    objectClass: ['organizationalUnit', 'top'],
    ou: normalizedName
  };

  try {
    await executeLDAP(svc.dn, svc.password, async (client) => {

      // ------------------------------------------------
      // CREATE OU
      // ------------------------------------------------

      await ldapAdd(client, ouDN, entry);

      // ------------------------------------------------
      // CREATE ADMIN GROUP
      // ------------------------------------------------

      const adminGroupDN =
        `cn=${normalizedName}_admins,ou=${name},${BASE_DN}`;

      await ldapAdd(client, adminGroupDN, {
        objectClass: ['groupOfNames', 'top'],
        cn: `${name}_admins`,
        member: [`uid=superadmin,ou=managers,${BASE_DN}`]
      });

      // ------------------------------------------------
      // CREATE SERVICE ACCOUNT
      // ------------------------------------------------

      const serviceDN =
        `uid=ldap_${normalizedName}_service,ou=services,${BASE_DN}`;

      await ldapAdd(client, serviceDN, {
        objectClass: [
          'inetOrgPerson',
          'organizationalPerson',
          'person',
          'top'
        ],
        uid: `ldap_${normalizedName}_service`,
        cn: `LDAP ${normalizedName} Service`,
        sn: 'Service',
        businessCategory: 'SERVICE',
        userPassword: `${normalizedName}service123`
      });

      // ------------------------------------------------
      // CREATE INFRA MAPPING
      // ------------------------------------------------

      // ------------------------------------------------
      // CREATE INFRA MAPPING
      // ------------------------------------------------

      const mappingDN =
        `cn=${normalizedName}_mapping,${LDAP_INFRA_OU}`;

      await ldapAdd(client, mappingDN, {
        objectClass: ['groupOfNames', 'top'],
        cn: `${normalizedName}_mapping`,
        member: [serviceDN],
        o: `${normalizedName}service123`
      });

      console.log(
        `INFRA MAPPING CREATED: ${mappingDN}`
      );
    });

    return res.status(201).json({ message: `Department ${name} successfully created.` });
  } catch (error) {
    console.error('Create department error:', error);
    if (error.name === 'InsufficientAccessRightsError' || error.message.includes('Insufficient Access Rights')) {
      return res.status(403).json({
        message: 'Security Containment Block: Insufficient privileges to create new OUs.'
      });
    }
    if (error.message.includes('Already exists')) {
      return res.status(409).json({ message: 'Department with this name already exists' });
    }
    return res.status(500).json({ message: 'Failed to create department', error: error.message });
  }
});

/**
 * Create a group CN under a target OU.
 * Only SUPER_ADMIN can create OU groups.
 */
app.post('/api/groups', authMiddleware, requireSuperAdmin, async (req, res) => {
  const { ou, cn, memberUids = [], memberDns = [] } = req.body;

  if (!ou || !cn) {
    return res.status(400).json({ message: 'Required fields: ou, cn' });
  }

  const normalizedOU = ou.trim();
  const normalizedCN = cn.trim();
  const requestedMemberDns = [
    ...memberDns.filter(Boolean).map((dn) => dn.trim()),
    ...memberUids.filter(Boolean).map((uid) => getUserDN(uid.trim(), normalizedOU))
  ];
  const uniqueMemberDns = [...new Set(requestedMemberDns)];

  if (uniqueMemberDns.length === 0) {
    return res.status(400).json({
      message: 'groupOfNames requires at least one member. Pass memberUids or memberDns.'
    });
  }

  const groupDN = getGroupDN(normalizedCN, normalizedOU);
  const svc = await getServiceAccount(req.user);

  try {
    await executeLDAP(svc.dn, svc.password, async (client) => {
      const ouDN = `ou=${normalizedOU},${BASE_DN}`;
      try {
        const existingOU = await ldapSearch(client, ouDN, {
          filter: '(objectClass=organizationalUnit)',
          scope: 'base'
        });

        if (existingOU.length === 0) {
          await ldapAdd(client, ouDN, {
            objectClass: ['organizationalUnit', 'top'],
            ou: normalizedOU
          });
        }
      } catch (ouError) {
        if (!ouError.message.includes('No Such Object')) {
          throw ouError;
        }

        await ldapAdd(client, ouDN, {
          objectClass: ['organizationalUnit', 'top'],
          ou: normalizedOU
        });
      }

      await ldapAdd(client, groupDN, {
        objectClass: ['groupOfNames', 'top'],
        cn: normalizedCN,
        member: uniqueMemberDns
      });
    });

    return res.status(201).json({
      message: `Group ${normalizedCN} created successfully in ou=${normalizedOU}.`,
      dn: groupDN,
      members: uniqueMemberDns
    });
  } catch (error) {
    console.error('Create group error:', error);
    if (error.message.includes('Already exists')) {
      return res.status(409).json({ message: 'Group already exists in that OU.' });
    }
    return res.status(500).json({ message: 'Failed to create group', error: error.message });
  }
});

/**
 * Add a member to an existing OU group.
 * Only SUPER_ADMIN can add OU group members.
 */
app.post('/api/groups/:cn/members', authMiddleware, requireSuperAdmin, async (req, res) => {
  const { cn } = req.params;
  const { ou, memberUid, memberDn } = req.body;

  if (!ou || (!memberUid && !memberDn)) {
    return res.status(400).json({ message: 'Required fields: ou and one of memberUid or memberDn' });
  }

  const normalizedOU = ou.trim();
  const normalizedCN = cn.trim();
  const normalizedMemberDn = (memberDn || getUserDN(memberUid.trim(), normalizedOU)).trim();
  const groupDN = getGroupDN(normalizedCN, normalizedOU);
  const svc = await getServiceAccount(req.user);

  try {
    await executeLDAP(svc.dn, svc.password, async (client) => {
      const existingGroup = await ldapSearch(client, groupDN, {
        filter: '(objectClass=groupOfNames)',
        scope: 'base'
      });

      if (existingGroup.length === 0) {
        throw new Error('GROUP_NOT_FOUND');
      }

      const currentMembers = existingGroup[0].member
        ? (Array.isArray(existingGroup[0].member) ? existingGroup[0].member : [existingGroup[0].member])
        : [];

      if (currentMembers.includes(normalizedMemberDn)) {
        throw new Error('MEMBER_EXISTS');
      }

      await ldapModify(client, groupDN, [
        new ldap.Change({
          operation: 'add',
          modification: new ldap.Attribute({
            type: 'member',
            values: [normalizedMemberDn]
          })
        })
      ]);
    });

    return res.json({
      message: `Added member to ${normalizedCN} in ou=${normalizedOU}.`,
      member: normalizedMemberDn
    });
  } catch (error) {
    console.error('Add group member error:', error);
    if (error.message === 'GROUP_NOT_FOUND') {
      return res.status(404).json({ message: 'Group not found in the target OU.' });
    }
    if (error.message === 'MEMBER_EXISTS') {
      return res.status(409).json({ message: 'Member already exists in this group.' });
    }
    return res.status(500).json({ message: 'Failed to add group member', error: error.message });
  }
});

/**
 * Search & List users inside the system.
 * Filters based on role:
 * - SUPER_ADMIN sees everything
 * - ADMIN sees only their department users
 * - USER sees only their own profile
 */
app.get('/api/users', authMiddleware, async (req, res) => {
  const user = req.user;
  const svc = await getServiceAccount(user);

  try {
    console.log('BOUND AS:', svc.dn);
    const users = await executeLDAP(svc.dn, svc.password, async (client) => {

      let searchBase = BASE_DN;
      let filter = '(objectClass=person)';
      let scope = 'sub';

      console.log("BIND TRY:");
      console.log("DN:", svc.dn);
      console.log("PASSWORD:", svc.password);
      // ------------------------------------------------
      // USER → ONLY SELF
      // ------------------------------------------------
      if (user.role === 'USER') {

        const normalizedUID =
          String(user.uid)
            .trim()
            .toLowerCase();

        const normalizedOU =
          String(user.ou)
            .trim()
            .toLowerCase();

        searchBase =
          `uid=${normalizedUID},ou=${normalizedOU},${BASE_DN}`;

        filter = '(objectClass=person)';

        scope = 'base';

        console.log(
          'USER SEARCH BASE:',
          searchBase
        );
      }

      // ------------------------------------------------
      // ADMIN → ONLY THEIR OU
      // ------------------------------------------------

      else if (user.role === 'ADMIN') {

        const normalizedOU =
          String(user.ou)
            .trim()
            .toLowerCase();

        searchBase =
          `ou=${normalizedOU},${BASE_DN}`;

        scope = 'sub';

        console.log(
          'ADMIN SEARCH BASE:',
          searchBase
        );
      }

      // ------------------------------------------------
      // SUPER_ADMIN → EVERYTHING
      // ------------------------------------------------

      const entries = await ldapSearch(client, searchBase, {
        filter,
        scope
      });

      console.log(
        'RAW LDAP ENTRIES BEFORE FILTER:',
        entries.map((entry) => entry.uid || entry.dn)
      );

      return entries;
    });

    const mappedUsers = users
      .map(mapLDAPUser)
      // Filter out service accounts from standard listing
      .filter(u => u.ou !== 'services');

    return res.json(mappedUsers);
  } catch (error) {
    console.error('Search users error:', error);
    return res.status(500).json({ message: 'Failed to query users list', error: error.message });
  }
});

/**
 * Retrieve specific user details by UID.
 */
app.get('/api/users/:uid', authMiddleware, requireSelfOrAdmin('uid'), async (req, res) => {
  const { uid } = req.params;
  const svc = await getServiceAccount(req.user);

  try {
    const users = await executeLDAP(svc.dn, svc.password, async (client) => {
      return await ldapSearch(client, BASE_DN, {
        filter: `(&(objectClass=person)(uid=${uid}))`,
        scope: 'sub'
      });
    });

    if (users.length === 0) {
      return res.status(404).json({ message: 'User not found' });
    }

    return res.json(mapLDAPUser(users[0]));
  } catch (error) {
    return res.status(500).json({ message: 'Failed to fetch user', error: error.message });
  }
});

/**
 * Create a new user.
 * Protected by primary Express RBAC middleware.
 * Binds as the user's corresponding service account.
 */
app.post('/api/users', authMiddleware, requireManageOU('ou'), async (req, res) => {
  const { uid, cn, sn, mail, mobile, title, employeeType, businessCategory, ou, userPassword } = req.body;

  if (!uid || !cn || !sn || !mail || !ou) {
    return res.status(400).json({ message: 'Required fields: uid, cn, sn, mail, ou' });
  }

  const userDN = `uid=${uid},ou=${ou},${BASE_DN}`;
  const svc = await getServiceAccount(req.user);

  const entry = {
    objectClass: ['inetOrgPerson', 'organizationalPerson', 'person', 'top'],
    cn,
    sn,
    mail,
    mobile: mobile || '',
    title: title || 'Employee',
    employeeType: employeeType || 'active',
    businessCategory: businessCategory || 'USER',
    uid,
    userPassword: userPassword || 'user123'
  };

  try {
    // For SUPER_ADMIN, auto-create the OU if it doesn't exist
    if (req.user.role === 'SUPER_ADMIN') {
      try {
        const ouDN = `ou=${ou},${BASE_DN}`;
        await executeLDAP(svc.dn, svc.password, async (client) => {
          return await ldapAdd(client, ouDN, {
            objectClass: ['organizationalUnit', 'top'],
            ou: ou
          });
        });
      } catch (ouError) {
        // If OU already exists, that's fine - continue with user creation
        if (!ouError.message.includes('Already exists') && !ouError.message.includes('already exists')) {
          console.error('Error creating OU:', ouError);
          // Don't fail the whole operation, just log it
        }
      }
    }

    await executeLDAP(svc.dn, svc.password, async (client) => {
      return await ldapAdd(client, userDN, entry);
    });

    return res.status(201).json({ message: `User ${uid} successfully created in ${ou}.` });
  } catch (error) {
    console.error('Create user error:', error);
    // Translate LDAP ACL blockages into helpful errors
    if (error.name === 'InsufficientAccessRightsError' || error.message.includes('Insufficient Access Rights')) {
      return res.status(403).json({
        message: 'Security Containment Block: Mapped service account possesses insufficient privileges to perform writes outside its OU.'
      });
    }
    return res.status(500).json({ message: 'Failed to create user', error: error.message });
  }
});

/**
 * Modify a user.
 * Protects fields based on user status (self vs admin).
 */
app.put('/api/users/:uid', authMiddleware, requireSelfOrAdmin('uid'), async (req, res) => {
  const { uid } = req.params;
  const updates = req.body;
  const svc = await getServiceAccount(req.user);

  try {
    // 1. Fetch current user from LDAP to verify details
    const existing = await executeLDAP(svc.dn, svc.password, async (client) => {
      return await ldapSearch(client, BASE_DN, {
        filter: `(&(objectClass=person)(uid=${uid}))`,
        scope: 'sub'
      });
    });

    if (existing.length === 0) {
      return res.status(404).json({ message: 'User not found' });
    }

    const currentUser = mapLDAPUser(existing[0]);
    const requestedOU = updates.ou?.trim();
    const isOUChange = Boolean(requestedOU && requestedOU !== currentUser.ou);
    const requestedRole = (updates.businessCategory || currentUser.businessCategory || 'USER').toUpperCase();

    // 2. Validate fields that are restricted during self-service
    if (isSelf(req.user, uid) && req.user.role !== 'SUPER_ADMIN') {
      const forbiddenSelfFields = ['businessCategory', 'employeeType', 'ou'];
      const hasForbiddenFields = forbiddenSelfFields.some(field => field in updates && updates[field] !== currentUser[field]);
      if (hasForbiddenFields) {
        return res.status(403).json({
          message: 'Security Policy Violation: Standard users cannot elevate their role, alter OUs, or modify status.'
        });
      }
    }

    if (isOUChange && req.user.role !== 'SUPER_ADMIN') {
      return res.status(403).json({
        message: 'Only SUPER_ADMIN can change a user department.'
      });
    }

    if (requestedOU === 'services') {
      return res.status(400).json({ message: 'Users cannot be moved into the services department.' });
    }

    // 3. Assemble LDAP modification changes
    const changes = [];
    const modifiableFields = ['cn', 'sn', 'mail', 'mobile', 'title', 'employeeType', 'businessCategory', 'userPassword'];

    modifiableFields.forEach(field => {
      if (updates[field] !== undefined && updates[field] !== currentUser[field]) {
        changes.push(
          new ldap.Change({
            operation: 'replace',
            modification: new ldap.Attribute({
              type: field,
              values: Array.isArray(updates[field]) ? updates[field] : [updates[field]]
            })
          })
        );
      }
    });

    if (changes.length === 0) {
      if (!isOUChange) {
        return res.json({ message: 'No modifications detected.' });
      }
    }

    let finalUserDN = currentUser.dn;
    let finalUserOU = currentUser.ou;

    await executeLDAP(svc.dn, svc.password, async (client) => {
      if (changes.length > 0) {
        await ldapModify(client, currentUser.dn, changes);
      }

      if (isOUChange) {
        const targetOU = requestedOU;
        const targetOUDN = `ou=${targetOU},${BASE_DN}`;
        try {
          const targetOUEntries = await ldapSearch(client, targetOUDN, {
            scope: 'base',
            filter: '(objectClass=organizationalUnit)'
          });

          if (targetOUEntries.length === 0) {
            await ldapAdd(client, targetOUDN, {
              objectClass: ['top', 'organizationalUnit'],
              ou: targetOU
            });
          }
        } catch (ouError) {
          if (!ouError.message.includes('No Such Object')) {
            throw ouError;
          }

          await ldapAdd(client, targetOUDN, {
            objectClass: ['top', 'organizationalUnit'],
            ou: targetOU
          });
        }

        const newDN = `uid=${uid},${targetOUDN}`;
        await ldapModifyDN(client, currentUser.dn, newDN);
        finalUserDN = newDN;
        finalUserOU = targetOU;
      }

      if (req.user.role === 'SUPER_ADMIN') {
        if (isOUChange) {
          await syncOUAdminGroupMembership(client, currentUser.dn, currentUser.ou, false);
        }

        await syncOUAdminGroupMembership(
          client,
          finalUserDN,
          finalUserOU,
          requestedRole === 'ADMIN'
        );
      }
    });

    return res.json({ message: `User profile ${uid} updated successfully.` });

  } catch (error) {
    console.error('Update user error:', error);
    if (error.name === 'InsufficientAccessRightsError' || error.message.includes('Insufficient Access Rights')) {
      return res.status(403).json({
        message: 'Security Containment Block: Mapped service account is restricted from performing operations under this subtree by LDAP ACLs.'
      });
    }
    return res.status(500).json({ message: 'Failed to update user', error: error.message });
  }
});

/**
 * Delete a user.
 * Protected by primary Express RBAC.
 */
app.delete('/api/users/:uid', authMiddleware, async (req, res) => {
  const { uid } = req.params;
  const { ou } = req.query; // Admin must supply the OU so RBAC check is fast

  if (!ou) {
    return res.status(400).json({ message: 'Target department (ou) query parameter is required to authorize deletion.' });
  }

  // Primary authorization check
  if (!canManageOU(req.user, ou)) {
    return res.status(403).json({ message: `Access denied. You cannot delete users inside the ${ou} department.` });
  }

  const userDN = `uid=${uid},ou=${ou},${BASE_DN}`;
  const svc = await getServiceAccount(req.user);

  try {
    await executeLDAP(svc.dn, svc.password, async (client) => {
      return await ldapDelete(client, userDN);
    });

    return res.json({ message: `User ${uid} successfully removed from DIT.` });
  } catch (error) {
    console.error('Delete user error:', error);
    if (error.name === 'InsufficientAccessRightsError' || error.message.includes('Insufficient Access Rights')) {
      return res.status(403).json({
        message: 'Security Containment Block: Mapped service account has been blocked from executing deletes on this subtree by LDAP ACL policies.'
      });
    }
    return res.status(500).json({ message: 'Failed to delete user', error: error.message });
  }
});


// Start server
app.listen(PORT, () => {
  console.log(`=================================================`);
  console.log(`Enterprise LDAP RBAC+ACL Backend running on port ${PORT}`);
  console.log(`LDAP connection targets: ${process.env.LDAP_URL}`); console.log(`=================================================`);
});
