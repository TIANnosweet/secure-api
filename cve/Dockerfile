# CVE-2018-3760 laboratory: a Sprockets asset server (Rails 5.0.7 asset
# pipeline component). The Sprockets version is a build argument so the
# vulnerable (3.7.1) and patched (3.7.2) builds differ in exactly one line.
FROM ruby:2.5

ARG SPROCKETS_VERSION=3.7.1

ENV LANG=C.UTF-8

RUN gem install rack -v 2.0.8 --no-document \
 && gem install sprockets -v ${SPROCKETS_VERSION} --no-document

WORKDIR /usr/src/blog
COPY app ./app
COPY config.ru .

EXPOSE 3000
CMD ["rackup", "-o", "0.0.0.0", "-p", "3000"]
