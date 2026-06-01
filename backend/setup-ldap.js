import ldap from 'ldapjs';
import dotenv from 'dotenv';

dotenv.config();

const LDAP_URL = process.env.LDAP_URL || 'ldap://localhost:389';
const BASE_DN = process.env.LDAP_BASE_DN || 'dc=company,dc=com';
const SERVICES_OU = `ou=services,${BASE_DN}`;

const ADMIN_DN = 'cn=admin,dc=company,dc=com';
const ADMIN_PASSWORD = 'admin';

const client = ldap.createClient({
  url: LDAP_URL
});

const serviceAccounts = [
  {
    dn: `cn=ldap_reader,${SERVICES_OU}`,
    entry: {
      objectClass: ['inetOrgPerson', 'top'],
      cn: 'ldap_reader',
      sn: 'service',
      userPassword: 'reader_password',
      description: 'Service account for searching mobile numbers and verifying OTP'
    }
  },
  {
    dn: `cn=ldap_superadmin,${SERVICES_OU}`,
    entry: {
      objectClass: ['inetOrgPerson', 'top'],
      cn: 'ldap_superadmin',
      sn: 'service',
      userPassword: 'superadmin_password',
      description: 'Service account for global management across all subtrees'
    }
  },
  {
    dn: `cn=ldap_audit_admin,${SERVICES_OU}`,
    entry: {
      objectClass: ['inetOrgPerson', 'top'],
      cn: 'ldap_audit_admin',
      sn: 'service',
      userPassword: 'audit_password',
      description: 'Service account restricted to ou=audit'
    }
  },
  {
    dn: `cn=ldap_developer_admin,${SERVICES_OU}`,
    entry: {
      objectClass: ['inetOrgPerson', 'top'],
      cn: 'ldap_developer_admin',
      sn: 'service',
      userPassword: 'developer_password',
      description: 'Service account restricted to ou=developer'
    }
  },
  {
    dn: `cn=ldap_tester_admin,${SERVICES_OU}`,
    entry: {
      objectClass: ['inetOrgPerson', 'top'],
      cn: 'ldap_tester_admin',
      sn: 'service',
      userPassword: 'tester_password',
      description: 'Service account restricted to ou=tester'
    }
  }
];

const checkAndCreateOU = (dn) => {
  return new Promise((resolve) => {
    client.search(dn, { scope: 'base' }, (err, res) => {
      let exists = false;
      if (err) {
        // OU does not exist, let's create it
        createOU(dn).then(resolve);
        return;
      }

      res.on('searchEntry', () => {
        exists = true;
      });

      res.on('error', () => {
        createOU(dn).then(resolve);
      });

      res.on('end', () => {
        if (exists) {
          console.log(`[LDAP Setup] Services OU is already present.`);
          resolve();
        } else {
          createOU(dn).then(resolve);
        }
      });
    });
  });
};

const createOU = (dn) => {
  return new Promise((resolve) => {
    const entry = {
      objectClass: ['organizationalUnit', 'top'],
      ou: 'services'
    };
    client.add(dn, entry, (err) => {
      if (err) {
        console.error(`[LDAP Setup] Failed to create services OU:`, err.message);
      } else {
        console.log(`[LDAP Setup] Created Services OU successfully.`);
      }
      resolve();
    });
  });
};

const createServiceAccount = (account) => {
  return new Promise((resolve) => {
    client.add(account.dn, account.entry, (err) => {
      if (err) {
        if (err.name === 'EntryAlreadyExistsError') {
          console.log(`[LDAP Setup] Service account ${account.dn} is already registered.`);
        } else {
          console.error(`[LDAP Setup] Error creating service account ${account.dn}:`, err.message);
        }
      } else {
        console.log(`[LDAP Setup] Successfully registered service account: ${account.dn}`);
      }
      resolve();
    });
  });
};

console.log(`[LDAP Setup] Connecting to LDAP at ${LDAP_URL}...`);

client.bind(ADMIN_DN, ADMIN_PASSWORD, async (err) => {
  if (err) {
    console.error('[LDAP Setup] Failed to bind as admin. Check your credentials.', err.message);
    process.exit(1);
  }

  console.log('[LDAP Setup] Admin bind successful. Setting up service accounts...');
  
  // 1. Ensure Services OU exists
  await checkAndCreateOU(SERVICES_OU);

  // 2. Add each service account
  for (const account of serviceAccounts) {
    await createServiceAccount(account);
  }

  console.log('[LDAP Setup] Migration complete.');
  client.unbind(() => {
    process.exit(0);
  });
});
