import lief, os, sys

path = sys.argv[1]
fnames = os.listdir(path)

for f in fnames:

	print('****** : {}{}'.format(path, f))

	exebin = lief.parse(filepath=path+f)

	if exebin.has_resources:
		res = exebin.resources

		res_manager = exebin.resources_manager

		print(res_manager.langs_available, res_manager.sublangs_available)

		if res_manager.has_manifest:
			print(res_manager.manifest)

		if res_manager.has_version:
			v = res_manager.version

			print(v)

		if res_manager.has_icons:
			for icon in res_manager.icons:
				print((icon.lang), icon.sublang)
