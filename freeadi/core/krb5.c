/*
 * This file is part of FreeADI. FreeADI is free software that is made
 * available under the MIT license. Consult the file "LICENSE" that is
 * distributed together with this file for the exact licensing terms.
 *
 * FreeADI is copyright (c) 2007 by the FreeADI authors. See the file
 * "AUTHORS" for a complete overview.
 */

#include <Python.h>
#include <krb5.h>


static PyObject *k5_error;

#define RETURN_ON_ERROR(code) \
    do if (code != 0) \
    { \
        const char *message; \
        message = krb5_get_error_message(ctx, code); \
        PyErr_Format(k5_error, message); \
        krb5_free_error_message(ctx, message); \
        return NULL; \
    } while (0)


static PyObject *
k5_get_init_creds_password(PyObject *self, PyObject *args)
{
    char *name, *password;
    krb5_context ctx;
    krb5_error_code code;
    krb5_ccache ccache;
    krb5_principal principal;
    krb5_get_init_creds_opt options;
    krb5_creds creds;

    if (!PyArg_ParseTuple(args, "ss", &name, &password))
        return NULL;

    /* Initialize parameters. */
    code = krb5_init_context(&ctx);
    RETURN_ON_ERROR(code);
    code = krb5_parse_name(ctx, name, &principal);
    RETURN_ON_ERROR(code);
    krb5_get_init_creds_opt_init(&options);
    memset(&creds, 0, sizeof (creds));

    /* Get the credentials. */
    code = krb5_get_init_creds_password(ctx, &creds, principal, password,
                                        NULL, NULL, 0, NULL, &options);
    RETURN_ON_ERROR(code);

    /* Store the credential in the credential cache. */
    code = krb5_cc_default(ctx, &ccache);
    RETURN_ON_ERROR(code);
    code = krb5_cc_initialize(ctx, ccache, principal);
    RETURN_ON_ERROR(code);
    code = krb5_cc_store_cred(ctx, ccache, &creds);
    RETURN_ON_ERROR(code);

    Py_INCREF(Py_None);
    return Py_None;
}


static PyObject *
k5_get_init_creds_keytab(PyObject *self, PyObject *args)
{
    char *name, *password;
    krb5_context ctx;
    krb5_error_code code;
    krb5_ccache ccache;
    krb5_principal principal;
    krb5_get_init_creds_opt options;
    krb5_creds creds;

    if (!PyArg_ParseTuple(args, "ss", &name, &password))
        return NULL;

    /* Initialize parameters. */
    code = krb5_init_context(&ctx);
    RETURN_ON_ERROR(code);
    code = krb5_parse_name(ctx, name, &principal);
    RETURN_ON_ERROR(code);
    krb5_get_init_creds_opt_init(&options);
    memset(&creds, 0, sizeof (creds));

    /* Get the credentials. */
    code = krb5_get_init_creds_keytab(ctx, &creds, principal,
                                      0, 0, NULL, &options);
    RETURN_ON_ERROR(code);

    /* Store the credential in the credential cache. */
    code = krb5_cc_default(ctx, &ccache);
    RETURN_ON_ERROR(code);
    code = krb5_cc_initialize(ctx, ccache, principal);
    RETURN_ON_ERROR(code);
    code = krb5_cc_store_cred(ctx, ccache, &creds);
    RETURN_ON_ERROR(code);

    Py_INCREF(Py_None);
    return Py_None;
}


static PyMethodDef Krb5Methods[] = 
{
    { "get_init_creds_password",
            (PyCFunction) k5_get_init_creds_password, METH_VARARGS },
    { "get_init_creds_keytab",
            (PyCFunction) k5_get_init_creds_keytab, METH_VARARGS },
    { NULL, NULL }
};

void
initkrb5(void)
{
    PyObject *module, *dict;

    initialize_krb5_error_table();

    module = Py_InitModule("krb5", Krb5Methods);
    dict = PyModule_GetDict(module);
    k5_error = PyErr_NewException("freeadi.krb5.Krb5Error", NULL, NULL);
    PyDict_SetItemString(dict, "Krb5Error", k5_error);
}
