import pkgutil
import sys


def load_all_modules_from_dir(dirname):

    modules = []
    for importer, package_name, _ in pkgutil.iter_modules([dirname]):
        full_package_name = '%s.%s' % (dirname, package_name)

        print(full_package_name)

        if ('_graph' in full_package_name) and not (full_package_name in sys.modules):
            module = importer.find_module(package_name).load_module(full_package_name)
            modules.append((module.__name__, module))

    return modules


a = load_all_modules_from_dir('graphs')

print(len(a))
exit(0)
 