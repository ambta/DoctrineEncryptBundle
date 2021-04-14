<?php

namespace Ambta\DoctrineEncryptBundle\Command;

use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;

/**
 * Get status of doctrine encrypt bundle and the database.
 *
 * @author Marcel van Nuil <marcel@ambta.com>
 * @author Michael Feinbier <michael@feinbier.net>
 */
class DoctrineEncryptStatusCommand extends AbstractCommand
{

    /**
     * {@inheritdoc}
     */
    protected function configure()
    {
        $this
            ->setName('doctrine:encrypt:status')
            ->setDescription('Get status of doctrine encrypt bundle and the database');
    }

    /**
     * {@inheritdoc}
     */
    protected function execute(InputInterface $input, OutputInterface $output)
    {
        $metaDataArray = $this->entityManager->getMetadataFactory()->getAllMetadata();

        $totalCount = 0;
        foreach($metaDataArray as $metaData) {
            if ($metaData->isMappedSuperclass) {
                continue;
            }

            $count = 0;
            $encryptedPropertiesCount = count($this->getEncryptionableProperties($metaData));
            if ($encryptedPropertiesCount > 0) {
                $totalCount += $encryptedPropertiesCount;
                $count += $encryptedPropertiesCount;
            }

            if ($count > 0) {
                $output->writeln(sprintf('<info>%s</info> has <info>%d</info> properties which are encrypted.', $metaData->name, $count));
            } else {
                $output->writeln(sprintf('<info>%s</info> has no properties which are encrypted.', $metaData->name));
            }
        }

        $output->writeln('');
        $output->writeln(sprintf('<info>%d</info> entities found which are containing <info>%d</info> encrypted properties.', count($metaDataArray), $totalCount));
        return Command::SUCCESS;
    }
}
