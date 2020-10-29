#include <Python.h>

static PyObject* say_hi(PyObject* self, PyObject* args)
{
    printf("Hello World!\n");
    return Py_None;
}

static PyMethodDef myMethods[] = {
    { "say_hi", say_hi, METH_NOARGS, "Prints Hello World!" },
    { NULL, NULL, 0, NULL }
};

static struct PyModuleDef myModule = {
    PyModuleDef_HEAD_INIT,
    "myModule",
    "Test Module",
    -1,
    myMethods
};

PyMODINIT_FUNC PyInit_myModule(void)
{
    return PyModule_Create(&myModule);
}

// python3 setup.py build
// python3 setup.py install
