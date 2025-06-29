import { Module } from '@nestjs/common';
import { AssignmentService } from './assignment.service';
import { AssignmentController } from './assignment.controller';
import { TypeOrmModule } from '@nestjs/typeorm';
import { User } from 'src/users/entities/user.entity';
import { Model } from 'src/model/entities/model.entity';
import { Assignment } from './entities/assignment.entity';
import { UsersModule } from 'src/users/users.module';
import { ModelModule } from 'src/model/model.module';
import { EnrollmentModule } from 'src/enrollment/enrollment.module';

@Module({
  imports:[TypeOrmModule.forFeature([Assignment,]),ModelModule,EnrollmentModule,],
  controllers: [AssignmentController],
  providers: [AssignmentService],
  exports:[AssignmentService]
})
export class AssignmentModule {}
