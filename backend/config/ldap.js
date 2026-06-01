import ldap from 'ldapjs';
import dotenv from 'dotenv';

dotenv.config();

const LDAP_URL =
  process.env.LDAP_URL;//|| 'ldap://localhost:389'

const LDAP_ADMIN_DN =
  process.env.LDAP_ROOT_DN;//|| 'cn=admin,dc=company,dc=com'

const LDAP_ADMIN_PASSWORD =
  process.env.LDAP_ROOT_PASSWORD;//|| 'admin'

const LDAP_INFRA_OU =
  process.env.LDAP_INFRA_OU;//|| 'ou=infra,dc=company,dc=com'

const LDAP_READER_DN =
  process.env.LDAP_READER_DN;

const LDAP_READER_PASSWORD =
  process.env.LDAP_READER_PASSWORD;

const LDAP_GLOBAL_ADMIN_DN =
  process.env.LDAP_GLOBAL_ADMIN_DN;

const LDAP_GLOBAL_ADMIN_PASSWORD =
  process.env.LDAP_GLOBAL_ADMIN_PASSWORD;

const escapeLDAPFilterValue = (value = '') => {
  return value
    .replace(/\\/g, '\\5c')
    .replace(/\*/g, '\\2a')
    .replace(/\(/g, '\\28')
    .replace(/\)/g, '\\29')
    .replace(/\0/g, '\\00');
};

/**
 * Executes LDAP operations safely with automatic bind/unbind handling.
 */
export const executeLDAP = (bindDN, password, callback) => {
  return new Promise((resolve, reject) => {

    const client = ldap.createClient({
      url: LDAP_URL,
      timeout: 5000,
      connectTimeout: 5000
    });

    client.on('error', (err) => {
      reject(err);
    });

    console.log('LDAP REAL BIND:');
    console.log('DN =>', bindDN);
    console.log('PASSWORD =>', password);

    client.bind(bindDN, password, async (bindErr) => {

      if (bindErr) {
        client.destroy();
        return reject(bindErr);
      }

      try {

        const result = await callback(client);

        client.unbind((unbindErr) => {
          if (unbindErr) {
            client.destroy();
          }
        });

        resolve(result);

      } catch (opErr) {

        client.unbind(() => {
          client.destroy();
        });

        reject(opErr);
      }
    });
  });
};

/**
 * Promise wrapper for LDAP search.
 */
export const ldapSearch = (client, base, options) => {

  return new Promise((resolve, reject) => {

    client.search(base, options, (err, res) => {

      if (err) {
        return reject(err);
      }

      const entries = [];

      res.on('searchEntry', (entry) => {

        const obj = {
          dn: entry.dn.toString()
        };

        entry.attributes.forEach((attr) => {

          const vals = attr.values;

          obj[attr.type] =
            vals.length === 1 ? vals[0] : vals;
        });

        entries.push(obj);
      });

      res.on('error', (searchErr) => {
        reject(searchErr);
      });

      res.on('end', () => {
        resolve(entries);
      });
    });
  });
};

/**
 * Dynamically resolves LDAP service account
 * based on OU mappings stored in:
 *
 * ou=infra,dc=company,dc=com
 *
 * Example mapping:
 *
 * dn: cn=developer_mapping,ou=infra,dc=company,dc=com
 * ouName: developer
 * bindDN: uid=ldap_developer_service,ou=services,dc=company,dc=com
 * bindPassword: devservice123
 */
export const getServiceAccount = async (user) => {

  // ---------------------------------------------------
  // Guest / OTP flow
  // ---------------------------------------------------

  if (!user) {

    return {
      dn: LDAP_READER_DN,
      password: LDAP_READER_PASSWORD
    };
  }

  // ---------------------------------------------------
  // Global superadmin gets full LDAP root access
  // ---------------------------------------------------

  if (user.role === 'SUPER_ADMIN') {

    return {
      dn: LDAP_ADMIN_DN,
      password: LDAP_ADMIN_PASSWORD
    };
  }

  // ---------------------------------------------------
  // Dynamic OU service mapping lookup
  // ---------------------------------------------------

  const mappings = await executeLDAP(
    LDAP_GLOBAL_ADMIN_DN,
    LDAP_GLOBAL_ADMIN_PASSWORD,
    async (client) => {
      const normalizedOU =
        (user.ou || '').trim().toLowerCase();
      const escapedOU = escapeLDAPFilterValue(normalizedOU);

      return await ldapSearch(
        client,
        LDAP_INFRA_OU,
        {
          scope: 'one',
          filter: `(|(cn=${escapedOU}_mapping)(description=${escapedOU}))`
        }
      );
    }
  );
  console.log("MAPPINGS:", JSON.stringify(mappings, null, 2));
  // ---------------------------------------------------
  // No mapping found
  // ---------------------------------------------------

  if (!mappings.length) {

    throw new Error(
      `No LDAP service mapping found for OU: ${user.ou}`
    );
  }
  // ---------------------------------------------------
  // Return dynamic service account
  // ---------------------------------------------------

  console.log('BIND TRY:');

  console.log(
    'DN:',
    Array.isArray(mappings[0].member)
      ? mappings[0].member[0]
      : mappings[0].member
  );

  console.log(
    'PASSWORD:',
    String(mappings[0].o).trim()
  );

  return {
    dn: Array.isArray(mappings[0].member)
      ? mappings[0].member[0]
      : mappings[0].member,

    password: String(mappings[0].o).trim()
  };
};

// ---------------------------------------------------
// LDAP ADD
// ---------------------------------------------------

export const ldapAdd = (client, dn, entry) => {

  return new Promise((resolve, reject) => {

    client.add(dn, entry, (err) => {

      if (err) {
        return reject(err);
      }

      resolve(true);
    });
  });
};

// ---------------------------------------------------
// LDAP MODIFY
// ---------------------------------------------------

export const ldapModify = (client, dn, changes) => {

  return new Promise((resolve, reject) => {

    client.modify(dn, changes, (err) => {

      if (err) {
        return reject(err);
      }

      resolve(true);
    });
  });
};

// ---------------------------------------------------
// LDAP DELETE
// ---------------------------------------------------

export const ldapDelete = (client, dn) => {

  return new Promise((resolve, reject) => {

    client.del(dn, (err) => {

      if (err) {
        return reject(err);
      }

      resolve(true);
    });
  });
};

// ---------------------------------------------------
// LDAP MODIFY DN
// ---------------------------------------------------

export const ldapModifyDN = (client, dn, newDN) => {

  return new Promise((resolve, reject) => {

    client.modifyDN(dn, newDN, (err) => {

      if (err) {
        return reject(err);
      }

      resolve(true);
    });
  });
};
