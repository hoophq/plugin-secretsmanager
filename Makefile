build: clean
	./scripts/build.py

publish:
	./scripts/publish.py

clean:
	rm -rf ./builds

.PHONY: build publish clean
