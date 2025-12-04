require "bundler/gem_tasks"

task default: :spec

desc "Run spec suite"
task :spec do
  if File.exist?("Gemfile")
    sh "bundle exec rspec"
  else
    sh "rspec"
  end
end
