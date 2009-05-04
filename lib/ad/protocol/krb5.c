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

#define RETURN_ON_ERROR(message, code) \
    do if (code != 0) \
    { \
        const char *error; \
        error = krb5_get_error_message(ctx, code); \
        PyErr_Format(k5_error, "%s: %s", message, error); \
        krb5_free_error_message(ctx, error); \
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
    RETURN_ON_ERROR("krb5_init_context()", code);
    code = krb5_parse_name(ctx, name, &principal);
    RETURN_ON_ERROR("krb5_parse_name()", code);
    krb5_get_init_creds_opt_init(&options);
    memset(&creds, 0, sizeof (creds));

    /* Get the credentials. */
    code = krb5_get_init_creds_password(ctx, &creds, principal, password,
                                        NULL, NULL, 0, NULL, &options);
    RETURN_ON_ERROR("krb5_get_init_creds_password()", code);

    /* Store the credential in the credential cache. */
    code = krb5_cc_default(ctx, &ccache);
    RETURN_ON_ERROR("krb5_cc_default()", code);
    code = krb5_cc_initialize(ctx, ccache, principal);
    RETURN_ON_ERROR("krb5_cc_initialize()", code);
    code = krb5_cc_store_cred(ctx, ccache, &creds);
    RETURN_ON_ERROR("krb5_cc_store_creds()", code);
    krb5_cc_close(ctx, ccache);

    Py_INCREF(Py_None);
    return Py_None;
}


static PyObject *
k5_get_init_creds_keytab(PyObject *self, PyObject *args)
{
    char *name, *ktname;
    krb5_context ctx;
    krb5_error_code code;
    krb5_keytab keytab;
    krb5_ccache ccache;
    krb5_principal principal;
    krb5_get_init_creds_opt options;
    krb5_creds creds;

    if (!PyArg_ParseTuple(args, "sz", &name, &ktname))
        return NULL;

    /* Initialize parameters. */
    code = krb5_init_context(&ctx);
    RETURN_ON_ERROR("krb5_init_context()", code);
    code = krb5_parse_name(ctx, name, &principal);
    RETURN_ON_ERROR("krb5_parse_name()", code);
    krb5_get_init_creds_opt_init(&options);
    memset(&creds, 0, sizeof (creds));

    /* Resolve keytab */
    if (ktname)
    {
	code = krb5_kt_resolve(ctx, ktname, &keytab);
	RETURN_ON_ERROR("krb5_kt_resolve()", code);
    } else
    {
	code = krb5_kt_default(ctx, &keytab);
	RETURN_ON_ERROR("krb5_kt_resolve()", code);
    }

    /* Get the credentials. */
    code = krb5_get_init_creds_keytab(ctx, &creds, principal,
                                      keytab, 0, NULL, &options);
    RETURN_ON_ERROR("krb5_get_init_creds_keytab()", code);

    /* Store the credential in the credential cache. */
    code = krb5_cc_default(ctx, &ccache);
    RETURN_ON_ERROR("krb5_cc_default()", code);
    code = krb5_cc_initialize(ctx, ccache, principal);
    RETURN_ON_ERROR("krb5_cc_initialize()", code);
    code = krb5_cc_store_cred(ctx, ccache, &creds);
    RETURN_ON_ERROR("krb5_cc_store_creds()", code);
    krb5_cc_close(ctx, ccache);

    Py_INCREF(Py_None);
    return Py_None;
}


static void
_k5_set_password_error(krb5_data *result_code_string, krb5_data *result_string)
{
    char *p1, *p2;
    
    p1 = malloc(result_code_string->length+1);
    if (p1 == NULL)
    {
	PyErr_NoMemory();
	return;
    }
    if (result_code_string->data)
    {
	strncpy(p1, result_code_string->data, result_code_string->length);
    }
    p1[result_code_string->length] = '\000';

    p2 = malloc(result_string->length+1);
    if (p1 == NULL)
    {
	PyErr_NoMemory();
	return;
    }
    if (result_string->data)
    {
	strncpy(p1, result_string->data, result_string->length);
    }
    p2[result_string->length] = '\000';

    PyErr_Format(k5_error, "%s%s%s", p1, (*p1 && *p2) ? ": " : "", p2);

    free(p1);
    free(p2);
}


static PyObject *
k5_set_password(PyObject *self, PyObject *args)
{
    int result_code;
    char *name, *newpass;
    krb5_context ctx;
    krb5_error_code code;
    krb5_principal principal;
    krb5_data result_code_string, result_string;
    krb5_ccache ccache;

    if (!PyArg_ParseTuple(args, "ss", &name, &newpass))
        return NULL;

    /* Initialize parameters. */
    code = krb5_init_context(&ctx);
    RETURN_ON_ERROR("krb5_init_context()", code);
    code = krb5_parse_name(ctx, name, &principal);
    RETURN_ON_ERROR("krb5_parse_name()", code);

    /* Get credentials */
    code = krb5_cc_default(ctx, &ccache);
    RETURN_ON_ERROR("krb5_cc_default()", code);

    /* Set password */
    code = krb5_set_password_using_ccache(ctx, ccache, newpass, principal,
					  &result_code, &result_code_string,
					  &result_string);
    RETURN_ON_ERROR("krb5_set_password_using_ccache()", code);

    /* Any other error? */
    if (result_code != 0)
    {
	_k5_set_password_error(&result_code_string, &result_string);
	return NULL;
    }

    /* Free up results. */
    if (result_code_string.data != NULL)
	free(result_code_string.data);
    if (result_string.data != NULL)
	free(result_string.data);

    Py_INCREF(Py_None);
    return Py_None;
}


static PyObject *
k5_change_password(PyObject *self, PyObject *args)
{
    int result_code;
    char *name, *oldpass, *newpass;
    krb5_context ctx;
    krb5_error_code code;
    krb5_principal principal;
    krb5_get_init_creds_opt options;
    krb5_creds creds;
    krb5_data result_code_string, result_string;

    if (!PyArg_ParseTuple(args, "sss", &name, &oldpass, &newpass))
        return NULL;

    /* Initialize parameters. */
    code = krb5_init_context(&ctx);
    RETURN_ON_ERROR("krb5_init_context()", code);
    code = krb5_parse_name(ctx, name, &principal);
    RETURN_ON_ERROR("krb5_parse_name()", code);

    /* Get credentials using the password. */
    krb5_get_init_creds_opt_init(&options);
    krb5_get_init_creds_opt_set_tkt_life(&options, 5*60);
    krb5_get_init_creds_opt_set_renew_life(&options, 0);
    krb5_get_init_creds_opt_set_forwardable(&options, 0);
    krb5_get_init_creds_opt_set_proxiable(&options, 0);
    memset(&creds, 0, sizeof (creds));
    code = krb5_get_init_creds_password(ctx, &creds, principal, oldpass,
					NULL, NULL, 0, "kadmin/changepw",
					&options);
    RETURN_ON_ERROR("krb5_get_init_creds_password()", code);

    code = krb5_change_password(ctx, &creds, newpass, &result_code,
				&result_code_string, &result_string);
    RETURN_ON_ERROR("krb5_change_password()", code);

    /* Any other error? */
    if (result_code != 0)
    {
	_k5_set_password_error(&result_code_string, &result_string);
	return NULL;
    }

    /* Free up results. */
    if (result_code_string.data != NULL)
	free(result_code_string.data);
    if (result_string.data != NULL)
	free(result_string.data);

    Py_INCREF(Py_None);
    return Py_None;
}


static PyObject *
k5_cc_default(PyObject *self, PyObject *args)
{
    krb5_context ctx;
    krb5_error_code code;
    krb5_ccache ccache;
    const char *name;
    PyObject *ret;

    code = krb5_init_context(&ctx);
    RETURN_ON_ERROR("krb5_init_context()", code);
    code = krb5_cc_default(ctx, &ccache);
    RETURN_ON_ERROR("krb5_cc_default()", code);
    name = krb5_cc_get_name(ctx, ccache);
    if (name == NULL)
    {
	PyErr_Format(k5_error, "krb5_cc_default() returned NULL");
	return NULL;
    }

    ret = PyString_FromString(name);
    if (ret == NULL)
	return ret;

    code = krb5_cc_close(ctx, ccache);
    RETURN_ON_ERROR("krb5_cc_close()", code);
    krb5_free_context(ctx);

    return ret;
}

static PyObject *
k5_cc_copy_creds(PyObject *self, PyObject *args)
{
    krb5_context ctx;
    char *namein, *nameout;
    krb5_error_code code;
    krb5_ccache ccin, ccout;
    krb5_principal principal;

    if (!PyArg_ParseTuple( args, "ss", &namein, &nameout))
	return NULL;

    code = krb5_init_context(&ctx);
    RETURN_ON_ERROR("krb5_init_context()", code);
    code = krb5_cc_resolve(ctx, namein, &ccin);
    RETURN_ON_ERROR("krb5_cc_resolve()", code);
    code = krb5_cc_get_principal(ctx, ccin, &principal);
    RETURN_ON_ERROR("krb5_cc_get_principal()", code);

    code = krb5_cc_resolve(ctx, nameout, &ccout);
    RETURN_ON_ERROR("krb5_cc_resolve()", code);
    code = krb5_cc_initialize(ctx, ccout, principal);
    RETURN_ON_ERROR("krb5_cc_get_initialize()", code);
    code = krb5_cc_copy_creds(ctx, ccin, ccout);
    RETURN_ON_ERROR("krb5_cc_copy_creds()", code);

    code = krb5_cc_close(ctx, ccin);
    RETURN_ON_ERROR("krb5_cc_close()", code);
    code = krb5_cc_close(ctx, ccout);
    RETURN_ON_ERROR("krb5_cc_close()", code);
    krb5_free_principal(ctx, principal);
    krb5_free_context(ctx);

    Py_INCREF(Py_None);
    return Py_None;
}


static PyObject *
k5_cc_get_principal(PyObject *self, PyObject *args)
{
    krb5_context ctx;
    char *ccname, *name;
    krb5_error_code code;
    krb5_ccache ccache;
    krb5_principal principal;
    PyObject *ret;

    if (!PyArg_ParseTuple( args, "s", &ccname))
	return NULL;

    code = krb5_init_context(&ctx);
    RETURN_ON_ERROR("krb5_init_context()", code);
    code = krb5_cc_resolve(ctx, ccname, &ccache);
    RETURN_ON_ERROR("krb5_cc_resolve()", code);
    code = krb5_cc_get_principal(ctx, ccache, &principal);
    RETURN_ON_ERROR("krb5_cc_get_principal()", code);
    code = krb5_unparse_name(ctx, principal, &name);
    RETURN_ON_ERROR("krb5_unparse_name()", code);

    ret = PyString_FromString(name);
    if (ret == NULL)
	return ret;

    code = krb5_cc_close(ctx, ccache);
    RETURN_ON_ERROR("krb5_cc_close()", code);
    krb5_free_unparsed_name(ctx, name);
    krb5_free_principal(ctx, principal);
    krb5_free_context(ctx);

    return ret;
}


static PyObject *
k5_c_valid_enctype(PyObject *self, PyObject *args)
{
    char *name;
    krb5_context ctx;
    krb5_enctype type;
    krb5_error_code code;
    krb5_boolean valid;
    PyObject *ret;

    if (!PyArg_ParseTuple( args, "s", &name))
	return NULL;

    code = krb5_init_context(&ctx);
    RETURN_ON_ERROR("krb5_init_context()", code);
    code = krb5_string_to_enctype(name, &type);
    RETURN_ON_ERROR("krb5_string_to_enctype()", code);
    valid = krb5_c_valid_enctype(type);
    ret = PyBool_FromLong((long) valid);
    krb5_free_context(ctx);

    return ret;
}


static PyMethodDef k5_methods[] = 
{
    { "get_init_creds_password",
            (PyCFunction) k5_get_init_creds_password, METH_VARARGS },
    { "get_init_creds_keytab",
            (PyCFunction) k5_get_init_creds_keytab, METH_VARARGS },
    { "set_password",
            (PyCFunction) k5_set_password, METH_VARARGS },
    { "change_password",
            (PyCFunction) k5_change_password, METH_VARARGS },
    { "cc_default",
	    (PyCFunction) k5_cc_default, METH_VARARGS },
    { "cc_copy_creds",
	    (PyCFunction) k5_cc_copy_creds, METH_VARARGS },
    { "cc_get_principal",
	    (PyCFunction) k5_cc_get_principal, METH_VARARGS },
    { "c_valid_enctype",
            (PyCFunction) k5_c_valid_enctype, METH_VARARGS },
    { NULL, NULL }
};


void
initkrb5(void)
{
    PyObject *module, *dict;

    initialize_krb5_error_table();

    module = Py_InitModule("krb5", k5_methods);
    dict = PyModule_GetDict(module);
    k5_error = PyErr_NewException("freeadi.protocol.krb5.Error", NULL, NULL);
    PyDict_SetItemString(dict, "Error", k5_error);
}
